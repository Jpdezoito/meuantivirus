"""Monitor comportamental de filesystem para detectar padroes de ransomware/wiper.

Implementacao baseada em polling (sem dependencias extras):
  - Snapshot periodico de metadados de arquivos em pastas criticas
  - Deteccao de picos de modificacao/criacao/exclusao em janelas curtas
  - Reforco para extensoes tipicas de ransomware
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
import logging
from pathlib import Path
import threading
import time
from typing import Callable

from app.services.ransomware_behavior_models import RansomwareBehaviorAlert
from app.services.risk_engine import RiskEngine, RiskSignal
from app.utils.logger import log_info, log_security_event, log_warning


class RansomwareBehaviorMonitorService:
    """Monitora alteracoes massivas em arquivos para identificar criptografia/wipe em massa."""

    POLL_INTERVAL = 2.8
    EVENT_WINDOW_SECONDS = 28.0
    ALERT_COOLDOWN_SECONDS = 130.0

    MAX_FILES_PER_ROOT = 5500
    MIN_FILE_SIZE = 1

    MASS_CHANGE_THRESHOLD = 34
    MASS_CREATE_THRESHOLD = 40
    MASS_DELETE_THRESHOLD = 24
    SUSPICIOUS_EXTENSION_THRESHOLD = 6

    MONITORED_FILE_EXTENSIONS = {
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
        ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".zip", ".7z", ".rar",
        ".sql", ".db", ".sqlite", ".json", ".xml", ".csv", ".psd", ".dwg",
    }

    SUSPICIOUS_RANSOM_EXTENSIONS = {
        ".locked", ".encrypted", ".crypt", ".wncry", ".wcry", ".petya", ".notpetya",
        ".ryk", ".ryuk", ".blackcat", ".conti", ".akira", ".deadbolt", ".mallox",
    }

    def __init__(
        self,
        logger: logging.Logger,
        *,
        alert_callback: Callable[[RansomwareBehaviorAlert], None],
        watched_roots: list[Path] | None = None,
    ) -> None:
        self.logger = logger
        self.alert_callback = alert_callback
        self._risk_engine = RiskEngine()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._watch_roots = watched_roots or self._default_roots()
        self._snapshots: dict[Path, dict[Path, tuple[float, int]]] = {}
        self._event_queues: dict[Path, deque[tuple[float, str, Path]]] = defaultdict(deque)
        self._last_alert: dict[Path, float] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._snapshots = {root: self._scan_root_state(root) for root in self._watch_roots}
        self._thread = threading.Thread(target=self._run_loop, name="SentinelaRansomGuard", daemon=True)
        self._thread.start()
        log_info(self.logger, f"[RansomGuard] Monitor ativo | pastas={[str(p) for p in self._watch_roots]}")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as error:
                log_warning(self.logger, f"[RansomGuard] Falha no polling: {error}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_once(self) -> None:
        now = time.time()
        for root in self._watch_roots:
            if not root.exists() or not root.is_dir():
                continue

            previous = self._snapshots.get(root, {})
            current = self._scan_root_state(root)
            self._snapshots[root] = current

            prev_keys = set(previous.keys())
            curr_keys = set(current.keys())
            created = curr_keys - prev_keys
            deleted = prev_keys - curr_keys
            changed = {
                path
                for path in (curr_keys & prev_keys)
                if current[path] != previous[path]
            }

            queue_ref = self._event_queues[root]
            for path in changed:
                queue_ref.append((now, "changed", path))
            for path in created:
                queue_ref.append((now, "created", path))
            for path in deleted:
                queue_ref.append((now, "deleted", path))

            self._trim_events(queue_ref, now)
            alert = self._build_alert_if_needed(root, queue_ref, now)
            if alert is None:
                continue

            last = self._last_alert.get(root)
            if last is not None and (now - last) < self.ALERT_COOLDOWN_SECONDS:
                continue
            self._last_alert[root] = now

            log_security_event(self.logger, f"[RansomGuard] {alert.short_summary} | score={alert.score}")
            try:
                self.alert_callback(alert)
            except Exception as error:
                log_warning(self.logger, f"[RansomGuard] Falha no callback de alerta: {error}")

    def _build_alert_if_needed(
        self,
        root: Path,
        events: deque[tuple[float, str, Path]],
        now: float,
    ) -> RansomwareBehaviorAlert | None:
        if not events:
            return None

        changed = 0
        created = 0
        deleted = 0
        suspicious_ext = 0

        for ts, kind, path in events:
            if now - ts > self.EVENT_WINDOW_SECONDS:
                continue
            if kind == "changed":
                changed += 1
            elif kind == "created":
                created += 1
            elif kind == "deleted":
                deleted += 1

            if path.suffix.lower() in self.SUSPICIOUS_RANSOM_EXTENSIONS:
                suspicious_ext += 1

        signals: list[RiskSignal] = []

        if changed >= self.MASS_CHANGE_THRESHOLD:
            signals.append(
                RiskSignal(
                    reason=f"Pico de modificacao de arquivos detectado ({changed} alteracoes em janela curta)",
                    weight=56,
                    category="encryption_massiva",
                    module="ransomware_behavior_monitor",
                )
            )

        if created >= self.MASS_CREATE_THRESHOLD:
            signals.append(
                RiskSignal(
                    reason=f"Criacao massiva de arquivos detectada ({created} novos arquivos)",
                    weight=40,
                    category="mass_file_activity",
                    module="ransomware_behavior_monitor",
                )
            )

        if deleted >= self.MASS_DELETE_THRESHOLD:
            signals.append(
                RiskSignal(
                    reason=f"Exclusao massiva de arquivos detectada ({deleted} exclusoes)",
                    weight=50,
                    category="wiper_activity",
                    module="ransomware_behavior_monitor",
                )
            )

        if suspicious_ext >= self.SUSPICIOUS_EXTENSION_THRESHOLD:
            signals.append(
                RiskSignal(
                    reason=(
                        f"Arquivos com extensoes tipicas de ransomware detectados "
                        f"({suspicious_ext} ocorrencias)"
                    ),
                    weight=62,
                    category="ransom_extension",
                    module="ransomware_behavior_monitor",
                )
            )

        if not signals:
            return None

        assessment = self._risk_engine.assess(signals=signals)
        if assessment.score <= 19:
            return None

        return RansomwareBehaviorAlert(
            watched_root=str(root),
            score=assessment.score,
            risk_level=assessment.risk_level,
            recommended_action=assessment.recommended_action,
            reasons=assessment.reasons,
            categories=assessment.categories,
            changed_files=changed,
            created_files=created,
            deleted_files=deleted,
            suspicious_extension_hits=suspicious_ext,
            timestamp=datetime.now(),
            analysis_modules=["ransomware_behavior_monitor"],
        )

    def _scan_root_state(self, root: Path) -> dict[Path, tuple[float, int]]:
        snapshot: dict[Path, tuple[float, int]] = {}
        scanned = 0

        try:
            iterator = root.rglob("*")
        except OSError:
            return snapshot

        for path in iterator:
            if scanned >= self.MAX_FILES_PER_ROOT:
                break
            if not path.is_file():
                continue

            suffix = path.suffix.lower()
            if suffix and suffix not in self.MONITORED_FILE_EXTENSIONS and suffix not in self.SUSPICIOUS_RANSOM_EXTENSIONS:
                continue

            try:
                stat = path.stat()
            except OSError:
                continue

            if stat.st_size < self.MIN_FILE_SIZE:
                continue

            snapshot[path] = (stat.st_mtime, stat.st_size)
            scanned += 1

        return snapshot

    def _trim_events(self, queue_ref: deque[tuple[float, str, Path]], now: float) -> None:
        while queue_ref and (now - queue_ref[0][0]) > self.EVENT_WINDOW_SECONDS:
            queue_ref.popleft()

    def _default_roots(self) -> list[Path]:
        home = Path.home()
        candidates = [
            home / "Desktop",
            home / "Documents",
            home / "Downloads",
            home / "Pictures",
        ]
        return [path for path in candidates if path.exists() and path.is_dir()]
