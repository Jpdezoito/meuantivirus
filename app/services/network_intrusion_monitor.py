"""Monitor comportamental de conexoes para detectar padroes de intrusao em rede.

Cobertura defensiva implementada:
  - Port scan outbound (muitas portas distintas em curto intervalo)
  - Brute force outbound (muitas tentativas em portas de autenticacao)
  - Reverse shell suspeita (shell/script com conexao externa ativa)
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
import ipaddress
import json
import logging
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Callable

import psutil

from app.core.risk import RiskLevel
from app.services.network_intrusion_models import NetworkIntrusionAlert
from app.services.risk_engine import RiskEngine, RiskSignal
from app.utils.logger import log_info, log_security_event, log_warning

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


class NetworkIntrusionMonitorService:
    """Monitora conexoes TCP em polling e gera alertas de comportamento suspeito."""

    POLL_INTERVAL = 2.0
    ALERT_COOLDOWN_SECONDS = 120.0

    PORT_SCAN_WINDOW = 25.0
    PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 18
    INBOUND_SCAN_WINDOW = 20.0
    INBOUND_SCAN_DISTINCT_LOCAL_PORTS_THRESHOLD = 9
    INBOUND_SCAN_MIN_EVENTS = 15
    INBOUND_SCAN_MIN_RATE_PER_SECOND = 2.5

    BRUTE_FORCE_WINDOW = 30.0
    BRUTE_FORCE_ATTEMPTS_THRESHOLD = 14

    SMB_WORM_WINDOW = 35.0
    SMB_WORM_HOSTS_THRESHOLD = 10

    SHELL_PROCESS_NAMES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "python.exe", "pythonw.exe", "bash.exe", "sh.exe", "nc.exe", "ncat.exe",
    }

    AUTH_PORTS = {21, 22, 25, 110, 143, 3389, 445, 3306, 5432, 5900}
    SMB_PORTS = {139, 445}
    COMMON_PORTS = {53, 80, 123, 443}
    AUTO_BLOCK_ON_INBOUND_SCAN = True
    AUTO_BLOCK_DURATION_SECONDS = 1800
    CONFIG_FILENAME = "network_guard_config.json"

    def __init__(
        self,
        logger: logging.Logger,
        *,
        data_dir: Path | None = None,
        alert_callback: Callable[[NetworkIntrusionAlert], None],
    ) -> None:
        self.logger = logger
        self.alert_callback = alert_callback
        self._risk_engine = RiskEngine()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._data_dir = data_dir
        self._config_path = (data_dir / self.CONFIG_FILENAME) if data_dir else None

        self._pid_ports: dict[int, deque[tuple[float, str, int]]] = defaultdict(deque)
        self._endpoint_hits: dict[tuple[int, str, int], deque[float]] = defaultdict(deque)
        self._pid_smb_hosts: dict[int, deque[tuple[float, str]]] = defaultdict(deque)
        self._remote_probe_ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._remote_probe_hits: dict[str, deque[float]] = defaultdict(deque)
        self._process_name_cache: dict[int, str] = {}
        self._last_alert: dict[str, float] = {}
        self._blocked_rules: dict[str, tuple[str, float]] = {}

        self._allowlist_ips: set[str] = set()
        self._allowlist_networks: list[ipaddress._BaseNetwork] = []
        self._auto_block_enabled = self.AUTO_BLOCK_ON_INBOUND_SCAN
        self._block_duration_seconds = self.AUTO_BLOCK_DURATION_SECONDS
        self._inbound_distinct_threshold = self.INBOUND_SCAN_DISTINCT_LOCAL_PORTS_THRESHOLD
        self._inbound_min_events = self.INBOUND_SCAN_MIN_EVENTS
        self._inbound_min_rate_per_second = self.INBOUND_SCAN_MIN_RATE_PER_SECOND
        self._load_guard_config()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="SentinelaNetworkMonitor",
            daemon=True,
        )
        self._thread.start()
        log_info(self.logger, "[NetGuard] Monitor de intrusao em rede ativo.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as error:
                log_warning(self.logger, f"[NetGuard] Falha no polling de rede: {error}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_once(self) -> None:
        now = time.time()
        records_by_pid: dict[int, list[tuple[str, int, int, str]]] = defaultdict(list)

        self._expire_blocked_rules(now)

        for conn in self._iter_external_tcp_connections():
            pid, remote_ip, remote_port, local_port, status = conn
            records_by_pid[pid].append((remote_ip, remote_port, local_port, status))

            if status in {"SYN_SENT", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"}:
                dq = self._pid_ports[pid]
                dq.append((now, remote_ip, remote_port))
                self._trim_pid_ports(dq, now)

            if remote_port in self.AUTH_PORTS:
                endpoint_key = (pid, remote_ip, remote_port)
                hits = self._endpoint_hits[endpoint_key]
                hits.append(now)
                self._trim_hits(hits, now)

            if remote_port in self.SMB_PORTS and status in {"SYN_SENT", "ESTABLISHED", "TIME_WAIT"}:
                smb_queue = self._pid_smb_hosts[pid]
                smb_queue.append((now, remote_ip))
                self._trim_smb_hosts(smb_queue, now)

            # Inbound scan: mesmo IP remoto tentando varias portas locais em curto tempo.
            if (
                status in {"SYN_RECV", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"}
                and not self._is_allowlisted_ip(remote_ip)
            ):
                probes = self._remote_probe_ports[remote_ip]
                probes.append((now, local_port))
                self._trim_remote_probes(probes, now)
                hits = self._remote_probe_hits[remote_ip]
                hits.append(now)
                self._trim_remote_hits(hits, now)

        for pid, entries in records_by_pid.items():
            process_name = self._resolve_process_name(pid)
            signals, remote_ip, remote_port, kind = self._build_signals_for_pid(
                pid,
                process_name,
                entries,
                now,
            )
            if not signals:
                continue

            assessment = self._risk_engine.assess(signals=signals)
            if assessment.score <= 19:
                continue

            alert_key = f"{kind}:{pid}:{remote_ip}:{remote_port}"
            if not self._should_emit_alert(alert_key, now):
                continue

            blocked_ip = None
            firewall_rule_name = None
            if (
                kind == "port_scan_inbound"
                and self._auto_block_enabled
                and not self._is_allowlisted_ip(remote_ip)
                and assessment.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}
            ):
                blocked, rule_name = self._try_block_ip(remote_ip, now)
                if blocked:
                    blocked_ip = remote_ip
                    firewall_rule_name = rule_name
                    signals.append(
                        RiskSignal(
                            reason=f"IP remoto {remote_ip} bloqueado automaticamente no firewall.",
                            weight=10,
                            category="auto_block",
                            module="network_intrusion_monitor",
                        )
                    )

            alert = NetworkIntrusionAlert(
                process_id=pid,
                process_name=process_name,
                kind=kind,
                remote_ip=remote_ip,
                remote_port=remote_port,
                score=assessment.score,
                risk_level=assessment.risk_level,
                recommended_action=assessment.recommended_action,
                reasons=assessment.reasons,
                categories=assessment.categories,
                timestamp=datetime.now(),
                analysis_modules=["network_intrusion_monitor"],
                blocked_ip=blocked_ip,
                firewall_rule_name=firewall_rule_name,
            )
            log_security_event(self.logger, f"[NetGuard] {alert.short_summary} | score={alert.score}")
            try:
                self.alert_callback(alert)
            except Exception as error:
                log_warning(self.logger, f"[NetGuard] Falha no callback de alerta: {error}")

    def _build_signals_for_pid(
        self,
        pid: int,
        process_name: str,
        entries: list[tuple[str, int, int, str]],
        now: float,
    ) -> tuple[list[RiskSignal], str, int, str]:
        signals: list[RiskSignal] = []
        top_ip = entries[0][0]
        top_port = entries[0][1]
        kind = "network_anomaly"

        # 1) Port scan outbound: muitas portas distintas para um ou mais hosts.
        ports_history = self._pid_ports.get(pid, deque())
        recent_distinct_ports = {port for ts, _ip, port in ports_history if now - ts <= self.PORT_SCAN_WINDOW}
        if len(recent_distinct_ports) >= self.PORT_SCAN_DISTINCT_PORTS_THRESHOLD:
            kind = "port_scan_outbound"
            signals.append(
                RiskSignal(
                    reason=(
                        f"Processo {process_name} tentou {len(recent_distinct_ports)} portas diferentes em curto intervalo"
                    ),
                    weight=62,
                    category="port_scan",
                    module="network_intrusion_monitor",
                )
            )

        # 2) Brute force outbound: muitas tentativas no mesmo endpoint de autenticacao.
        brute_peak = 0
        brute_target: tuple[str, int] | None = None
        for remote_ip, remote_port, _local_port, _status in entries:
            if remote_port not in self.AUTH_PORTS:
                continue
            hits = self._endpoint_hits.get((pid, remote_ip, remote_port), deque())
            count = sum(1 for ts in hits if now - ts <= self.BRUTE_FORCE_WINDOW)
            if count > brute_peak:
                brute_peak = count
                brute_target = (remote_ip, remote_port)

        if brute_peak >= self.BRUTE_FORCE_ATTEMPTS_THRESHOLD and brute_target is not None:
            kind = "brute_force_outbound"
            top_ip, top_port = brute_target
            signals.append(
                RiskSignal(
                    reason=(
                        f"Padrao de brute force detectado: {brute_peak} tentativas para {top_ip}:{top_port}"
                    ),
                    weight=54,
                    category="brute_force",
                    module="network_intrusion_monitor",
                )
            )

        # 3) Reverse shell suspeita: shell/script com conexao externa ativa.
        lowered = process_name.lower()
        if lowered in self.SHELL_PROCESS_NAMES:
            suspicious = [
                (ip, port)
                for ip, port, status in entries
                if status == "ESTABLISHED" and port not in self.COMMON_PORTS
            ]
            if suspicious:
                kind = "reverse_shell_suspeita"
                top_ip, top_port = suspicious[0]
                signals.append(
                    RiskSignal(
                        reason=(
                            f"Shell/script ({process_name}) com conexao externa estabelecida para {top_ip}:{top_port}"
                        ),
                        weight=58,
                        category="reverse_shell",
                        module="network_intrusion_monitor",
                    )
                )

        # 4) Lateral movement SMB: muitos hosts distintos em 445/139 rapidamente.
        smb_hosts_queue = self._pid_smb_hosts.get(pid, deque())
        distinct_smb_hosts = {
            host
            for ts, host in smb_hosts_queue
            if now - ts <= self.SMB_WORM_WINDOW
        }
        if len(distinct_smb_hosts) >= self.SMB_WORM_HOSTS_THRESHOLD:
            kind = "smb_worm_lateral"
            signals.append(
                RiskSignal(
                    reason=(
                        f"Padrao de propagacao SMB detectado: {len(distinct_smb_hosts)} hosts distintos via 445/139"
                    ),
                    weight=66,
                    category="lateral_movement_smb",
                    module="network_intrusion_monitor",
                )
            )

        # 5) Port scan inbound: mesmo IP remoto atingindo varias portas locais.
        inbound_candidate_ip, inbound_distinct, inbound_events, inbound_rate = self._detect_inbound_scan(entries, now)
        if (
            inbound_candidate_ip
            and inbound_distinct >= self._inbound_distinct_threshold
            and inbound_events >= self._inbound_min_events
            and inbound_rate >= self._inbound_min_rate_per_second
        ):
            kind = "port_scan_inbound"
            top_ip = inbound_candidate_ip
            signals.append(
                RiskSignal(
                    reason=(
                        f"IP remoto {inbound_candidate_ip} fez burst inbound: "
                        f"{inbound_events} eventos, {inbound_distinct} portas locais, {inbound_rate:.1f} ev/s"
                    ),
                    weight=68,
                    category="port_scan_inbound",
                    module="network_intrusion_monitor",
                )
            )

        return signals, top_ip, top_port, kind

    def _iter_external_tcp_connections(self):
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, psutil.Error, OSError):
            return []

        records: list[tuple[int, str, int, int, str]] = []
        for conn in connections:
            if conn.pid is None or not conn.raddr:
                continue

            remote_ip = getattr(conn.raddr, "ip", "")
            remote_port = int(getattr(conn.raddr, "port", 0) or 0)
            local_port = int(getattr(conn.laddr, "port", 0) or 0)
            if not remote_ip or remote_port <= 0:
                continue
            if local_port <= 0:
                continue
            if self._is_local_or_private_ip(remote_ip):
                continue

            records.append((int(conn.pid), remote_ip, remote_port, local_port, conn.status))

        return records

    @staticmethod
    def _is_local_or_private_ip(ip: str) -> bool:
        ip = ip.lower()
        return (
            ip.startswith("127.")
            or ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("localhost")
            or ip.startswith("::1")
            or ip.startswith("fe80:")
        )

    def _resolve_process_name(self, pid: int) -> str:
        cached = self._process_name_cache.get(pid)
        if cached:
            return cached
        try:
            name = psutil.Process(pid).name() or f"pid-{pid}"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            name = f"pid-{pid}"
        self._process_name_cache[pid] = name
        return name

    def _should_emit_alert(self, alert_key: str, now: float) -> bool:
        last = self._last_alert.get(alert_key)
        if last is not None and (now - last) < self.ALERT_COOLDOWN_SECONDS:
            return False
        self._last_alert[alert_key] = now
        return True

    def _trim_pid_ports(self, dq: deque[tuple[float, str, int]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.PORT_SCAN_WINDOW:
            dq.popleft()

    def _trim_hits(self, dq: deque[float], now: float) -> None:
        while dq and (now - dq[0]) > self.BRUTE_FORCE_WINDOW:
            dq.popleft()

    def _trim_smb_hosts(self, dq: deque[tuple[float, str]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.SMB_WORM_WINDOW:
            dq.popleft()

    def _trim_remote_probes(self, dq: deque[tuple[float, int]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.INBOUND_SCAN_WINDOW:
            dq.popleft()

    def _trim_remote_hits(self, dq: deque[float], now: float) -> None:
        while dq and (now - dq[0]) > self.INBOUND_SCAN_WINDOW:
            dq.popleft()

    def _detect_inbound_scan(
        self,
        entries: list[tuple[str, int, int, str]],
        now: float,
    ) -> tuple[str | None, int, int, float]:
        candidate_ip = None
        candidate_count = 0
        candidate_events = 0
        candidate_rate = 0.0
        for remote_ip, _remote_port, _local_port, _status in entries:
            if self._is_allowlisted_ip(remote_ip):
                continue
            probes = self._remote_probe_ports.get(remote_ip, deque())
            distinct_ports = {port for ts, port in probes if now - ts <= self.INBOUND_SCAN_WINDOW}
            hits = self._remote_probe_hits.get(remote_ip, deque())
            recent_hits = [ts for ts in hits if now - ts <= self.INBOUND_SCAN_WINDOW]
            events = len(recent_hits)
            if events <= 1:
                rate = 0.0
            else:
                span = max(recent_hits[-1] - recent_hits[0], 1e-6)
                rate = events / max(span, 1.0)
            if len(distinct_ports) > candidate_count:
                candidate_ip = remote_ip
                candidate_count = len(distinct_ports)
                candidate_events = events
                candidate_rate = rate
        return candidate_ip, candidate_count, candidate_events, candidate_rate

    def _try_block_ip(self, remote_ip: str, now: float) -> tuple[bool, str | None]:
        current = self._blocked_rules.get(remote_ip)
        if current is not None and current[1] > now:
            return False, None
        if self._is_local_or_private_ip(remote_ip):
            return False, None
        if self._is_allowlisted_ip(remote_ip):
            return False, None
        if not sys.platform.startswith("win"):
            return False, None

        rule_name = f"SentinelaPC_AutoBlock_{remote_ip}"
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={remote_ip}",
            "enable=yes",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as error:
            log_warning(self.logger, f"[NetGuard] Falha ao bloquear IP {remote_ip}: {error}")
            return False, None

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or "erro desconhecido"
            log_warning(self.logger, f"[NetGuard] Nao foi possivel bloquear {remote_ip}: {details}")
            return False, None

        expires_at = now + max(float(self._block_duration_seconds), 60.0)
        self._blocked_rules[remote_ip] = (rule_name, expires_at)
        ttl = int(max(0.0, expires_at - now))
        log_info(
            self.logger,
            f"[NetGuard] IP bloqueado automaticamente: {remote_ip} | regra={rule_name} | ttl={ttl}s",
        )
        return True, rule_name

    def _expire_blocked_rules(self, now: float) -> None:
        if not self._blocked_rules:
            return
        if not sys.platform.startswith("win"):
            return

        expired = [ip for ip, (_rule, until) in self._blocked_rules.items() if until <= now]
        for remote_ip in expired:
            rule_name, _until = self._blocked_rules.get(remote_ip, ("", 0.0))
            if not rule_name:
                self._blocked_rules.pop(remote_ip, None)
                continue
            if self._try_remove_block_rule(rule_name, remote_ip):
                self._blocked_rules.pop(remote_ip, None)

    def _try_remove_block_rule(self, rule_name: str, remote_ip: str) -> bool:
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as error:
            log_warning(self.logger, f"[NetGuard] Falha ao remover regra {rule_name}: {error}")
            return False

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or "erro desconhecido"
            log_warning(self.logger, f"[NetGuard] Nao foi possivel remover regra {rule_name}: {details}")
            return False

        log_info(self.logger, f"[NetGuard] Regra expirada removida: {rule_name} ({remote_ip})")
        return True

    def _is_allowlisted_ip(self, ip_text: str) -> bool:
        ip_text = (ip_text or "").strip()
        if not ip_text:
            return False
        if ip_text in self._allowlist_ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        return any(ip_obj in net for net in self._allowlist_networks)

    def _load_guard_config(self) -> None:
        if self._config_path is None:
            return

        default_config = {
            "allowlist_ips": [],
            "allowlist_cidrs": [],
            "auto_block_enabled": True,
            "auto_block_duration_seconds": self.AUTO_BLOCK_DURATION_SECONDS,
            "inbound_scan_distinct_ports_threshold": self.INBOUND_SCAN_DISTINCT_LOCAL_PORTS_THRESHOLD,
            "inbound_scan_min_events": self.INBOUND_SCAN_MIN_EVENTS,
            "inbound_scan_min_rate_per_second": self.INBOUND_SCAN_MIN_RATE_PER_SECOND,
        }

        raw_config = default_config
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            if self._config_path.exists():
                raw_config = json.loads(self._config_path.read_text(encoding="utf-8"))
            else:
                self._config_path.write_text(
                    json.dumps(default_config, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
        except Exception as error:
            log_warning(self.logger, f"[NetGuard] Falha ao carregar config, usando defaults: {error}")
            raw_config = default_config

        allow_ips = raw_config.get("allowlist_ips", [])
        if isinstance(allow_ips, list):
            self._allowlist_ips = {
                str(item).strip()
                for item in allow_ips
                if str(item).strip()
            }

        allow_cidrs = raw_config.get("allowlist_cidrs", [])
        parsed_networks: list[ipaddress._BaseNetwork] = []
        if isinstance(allow_cidrs, list):
            for item in allow_cidrs:
                text = str(item).strip()
                if not text:
                    continue
                try:
                    parsed_networks.append(ipaddress.ip_network(text, strict=False))
                except ValueError:
                    log_warning(self.logger, f"[NetGuard] CIDR invalido em allowlist: {text}")
        self._allowlist_networks = parsed_networks

        self._auto_block_enabled = bool(raw_config.get("auto_block_enabled", True))

        try:
            self._block_duration_seconds = int(raw_config.get("auto_block_duration_seconds", self.AUTO_BLOCK_DURATION_SECONDS))
        except (TypeError, ValueError):
            self._block_duration_seconds = self.AUTO_BLOCK_DURATION_SECONDS

        try:
            self._inbound_distinct_threshold = int(
                raw_config.get("inbound_scan_distinct_ports_threshold", self.INBOUND_SCAN_DISTINCT_LOCAL_PORTS_THRESHOLD)
            )
        except (TypeError, ValueError):
            self._inbound_distinct_threshold = self.INBOUND_SCAN_DISTINCT_LOCAL_PORTS_THRESHOLD

        try:
            self._inbound_min_events = int(raw_config.get("inbound_scan_min_events", self.INBOUND_SCAN_MIN_EVENTS))
        except (TypeError, ValueError):
            self._inbound_min_events = self.INBOUND_SCAN_MIN_EVENTS

        try:
            self._inbound_min_rate_per_second = float(
                raw_config.get("inbound_scan_min_rate_per_second", self.INBOUND_SCAN_MIN_RATE_PER_SECOND)
            )
        except (TypeError, ValueError):
            self._inbound_min_rate_per_second = self.INBOUND_SCAN_MIN_RATE_PER_SECOND

        self._block_duration_seconds = max(60, self._block_duration_seconds)
        self._inbound_distinct_threshold = max(4, self._inbound_distinct_threshold)
        self._inbound_min_events = max(6, self._inbound_min_events)
        self._inbound_min_rate_per_second = max(0.5, self._inbound_min_rate_per_second)

        log_info(
            self.logger,
            (
                "[NetGuard] Config carregada | "
                f"allow_ips={len(self._allowlist_ips)} allow_cidrs={len(self._allowlist_networks)} "
                f"autoblock={self._auto_block_enabled} ttl={self._block_duration_seconds}s "
                f"inbound(th={self._inbound_distinct_threshold}, events={self._inbound_min_events}, "
                f"rate={self._inbound_min_rate_per_second:.1f}/s)"
            ),
        )
