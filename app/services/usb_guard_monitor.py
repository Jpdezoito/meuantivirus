"""Monitor de protecao USB/BadUSB com whitelist e correlacao comportamental.

Recursos:
  - Descoberta de dispositivos USB/HID conectados
  - Whitelist local persistente de devices autorizados
  - Alerta para novo teclado/HID nao autorizado
  - Correlacao com execucao suspeita de shell logo apos insercao (BadUSB)
"""

from __future__ import annotations

from datetime import datetime
import json
import logging
from pathlib import Path
import subprocess
import threading
import time
from typing import Callable

import psutil

from app.services.risk_engine import RiskEngine, RiskSignal
from app.services.usb_guard_models import UsbSecurityAlert
from app.utils.logger import log_info, log_security_event, log_warning


class UsbGuardMonitorService:
    """Monitora dispositivos USB e sinais de HID injection (BadUSB)."""

    POLL_INTERVAL = 2.0
    ALERT_COOLDOWN_SECONDS = 120.0
    HID_CORRELATION_WINDOW = 90.0

    SHELL_SUSPICIOUS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe", "certutil.exe",
    }

    COMMAND_MARKERS = {
        "-encodedcommand", "invoke-expression", "downloadstring", "frombase64string",
        "invoke-webrequest", "iwr ", "curl ", "wget ", " start-process ", "cmd /c",
    }

    SUSPICIOUS_DEVICE_MARKERS = {
        "flipper", "rubber", "ducky", "badusb", "digispark", "teensy", "composite",
    }

    def __init__(
        self,
        logger: logging.Logger,
        *,
        data_dir: Path,
        alert_callback: Callable[[UsbSecurityAlert], None],
    ) -> None:
        self.logger = logger
        self.alert_callback = alert_callback
        self._risk_engine = RiskEngine()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._known_devices: dict[str, dict[str, str]] = {}
        self._trusted_ids: set[str] = set()
        self._last_alert: dict[str, float] = {}
        self._recent_untrusted_hid_insertions: list[tuple[float, str]] = []
        self._last_process_scan_time = time.time() - 3.0

        self._whitelist_file = data_dir / "usb_whitelist.json"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._load_whitelist()
        current = self._enumerate_usb_devices()

        # Primeiro start: baseline para evitar avalanche de alertas em devices ja conectados
        if not self._trusted_ids:
            self._trusted_ids = {dev["instance_id"] for dev in current}
            self._save_whitelist()
            log_info(self.logger, f"[USBGuard] Baseline de whitelist criada com {len(self._trusted_ids)} dispositivo(s).")

        self._known_devices = {dev["instance_id"]: dev for dev in current}
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="SentinelaUsbGuard", daemon=True)
        self._thread.start()
        log_info(self.logger, "[USBGuard] Monitor USB/BadUSB ativo.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)

    def approve_device(self, instance_id: str) -> bool:
        """Aprova um dispositivo na whitelist local."""
        if not instance_id:
            return False
        self._trusted_ids.add(instance_id)
        self._save_whitelist()
        return True

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as error:
                log_warning(self.logger, f"[USBGuard] Falha no polling USB: {error}")
            self._stop_event.wait(self.POLL_INTERVAL)

    def _poll_once(self) -> None:
        now = time.time()
        current_devices = self._enumerate_usb_devices()
        current_map = {dev["instance_id"]: dev for dev in current_devices}

        # Novo device conectado
        for instance_id, device in current_map.items():
            if instance_id in self._known_devices:
                continue
            self._handle_new_device(device, now)

        self._known_devices = current_map
        self._correlate_recent_hid_insertion_with_processes(now)
        self._trim_recent_hid(now)

    def _handle_new_device(self, device: dict[str, str], now: float) -> None:
        instance_id = device["instance_id"]
        if instance_id in self._trusted_ids:
            return

        name = device.get("friendly_name", "USB device")
        dev_class = device.get("device_class", "Unknown")
        lower_name = name.lower()

        signals: list[RiskSignal] = [
            RiskSignal(
                reason=f"Dispositivo USB nao autorizado conectado: {name}",
                weight=28,
                category="usb_new_untrusted",
                module="usb_guard_monitor",
            )
        ]

        is_hid_keyboard_like = dev_class.lower() in {"keyboard", "hidclass"}
        if is_hid_keyboard_like:
            self._recent_untrusted_hid_insertions.append((now, instance_id))
            signals.append(
                RiskSignal(
                    reason="Dispositivo HID/teclado nao autorizado conectado",
                    weight=34,
                    category="badusb_hid",
                    module="usb_guard_monitor",
                )
            )

        if any(marker in lower_name for marker in self.SUSPICIOUS_DEVICE_MARKERS):
            signals.append(
                RiskSignal(
                    reason=f"Assinatura de dispositivo USB potencialmente ofensivo detectada: {name}",
                    weight=22,
                    category="usb_suspicious_signature",
                    module="usb_guard_monitor",
                )
            )

        self._emit_alert(
            now,
            kind="usb_device_untrusted",
            device=device,
            signals=signals,
        )

    def _correlate_recent_hid_insertion_with_processes(self, now: float) -> None:
        if not self._recent_untrusted_hid_insertions:
            self._last_process_scan_time = now
            return

        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "create_time"]):
            try:
                created = float(proc.info.get("create_time") or 0.0)
            except Exception:
                continue
            if created <= self._last_process_scan_time:
                continue

            name = str(proc.info.get("name") or "").lower()
            if name not in self.SHELL_SUSPICIOUS:
                continue

            cmdline_parts = proc.info.get("cmdline") or []
            cmdline = " ".join(str(x) for x in cmdline_parts).lower()
            if not cmdline:
                continue

            if not any(marker in cmdline for marker in self.COMMAND_MARKERS):
                continue

            if not self._has_recent_untrusted_hid(created):
                continue

            signals = [
                RiskSignal(
                    reason=(
                        f"Processo shell suspeito iniciado logo apos insercao HID: {name}"
                    ),
                    weight=58,
                    category="badusb_command_injection",
                    module="usb_guard_monitor",
                ),
                RiskSignal(
                    reason="Padrao de comando compativel com injeção automatizada por teclado",
                    weight=42,
                    category="keystroke_injection",
                    module="usb_guard_monitor",
                ),
            ]
            device_stub = {
                "instance_id": "hid-recent-untrusted",
                "friendly_name": name,
                "device_class": "HID correlation",
            }
            self._emit_alert(
                now,
                kind="badusb_hid_injection",
                device=device_stub,
                signals=signals,
            )
            break

        self._last_process_scan_time = now

    def _has_recent_untrusted_hid(self, process_create_time: float) -> bool:
        for insertion_time, _instance_id in self._recent_untrusted_hid_insertions:
            if 0 <= (process_create_time - insertion_time) <= self.HID_CORRELATION_WINDOW:
                return True
        return False

    def _trim_recent_hid(self, now: float) -> None:
        self._recent_untrusted_hid_insertions = [
            (ts, instance_id)
            for ts, instance_id in self._recent_untrusted_hid_insertions
            if (now - ts) <= self.HID_CORRELATION_WINDOW
        ]

    def _emit_alert(self, now: float, *, kind: str, device: dict[str, str], signals: list[RiskSignal]) -> None:
        if not signals:
            return

        device_id = device.get("instance_id", "unknown")
        alert_key = f"{kind}:{device_id}"
        last = self._last_alert.get(alert_key)
        if last is not None and (now - last) < self.ALERT_COOLDOWN_SECONDS:
            return
        self._last_alert[alert_key] = now

        assessment = self._risk_engine.assess(signals=signals)
        if assessment.score <= 19:
            return

        alert = UsbSecurityAlert(
            kind=kind,
            score=assessment.score,
            risk_level=assessment.risk_level,
            recommended_action=assessment.recommended_action,
            reasons=assessment.reasons,
            categories=assessment.categories,
            device_instance_id=device_id,
            device_name=device.get("friendly_name", "USB device"),
            device_class=device.get("device_class", "Unknown"),
            timestamp=datetime.now(),
            analysis_modules=["usb_guard_monitor"],
        )
        log_security_event(self.logger, f"[USBGuard] {alert.short_summary} | score={alert.score}")
        try:
            self.alert_callback(alert)
        except Exception as error:
            log_warning(self.logger, f"[USBGuard] Falha no callback de alerta: {error}")

    def _enumerate_usb_devices(self) -> list[dict[str, str]]:
        command = (
            "Get-PnpDevice -PresentOnly | "
            "Where-Object {($_.Class -eq 'Keyboard' -or $_.Class -eq 'HIDClass' -or $_.Class -eq 'USB') -and $_.InstanceId -like 'USB*'} | "
            "Select-Object InstanceId, FriendlyName, Class, Manufacturer, Status | ConvertTo-Json -Depth 3"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
        except Exception:
            return []

        raw = (completed.stdout or "").strip()
        if not raw:
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        items: list[dict[str, object]]
        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = [item for item in data if isinstance(item, dict)]
        else:
            items = []

        devices: list[dict[str, str]] = []
        for item in items:
            instance_id = str(item.get("InstanceId") or "").strip()
            if not instance_id:
                continue
            devices.append(
                {
                    "instance_id": instance_id,
                    "friendly_name": str(item.get("FriendlyName") or "USB device").strip(),
                    "device_class": str(item.get("Class") or "Unknown").strip(),
                    "manufacturer": str(item.get("Manufacturer") or "").strip(),
                    "status": str(item.get("Status") or "").strip(),
                }
            )

        return devices

    def _load_whitelist(self) -> None:
        self._trusted_ids = set()
        if not self._whitelist_file.exists():
            return
        try:
            payload = json.loads(self._whitelist_file.read_text(encoding="utf-8"))
            ids = payload.get("trusted_instance_ids") or []
            if isinstance(ids, list):
                self._trusted_ids = {str(item).strip() for item in ids if str(item).strip()}
        except Exception as error:
            log_warning(self.logger, f"[USBGuard] Falha ao ler whitelist USB: {error}")

    def _save_whitelist(self) -> None:
        try:
            self._whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "trusted_instance_ids": sorted(self._trusted_ids),
                "updated_at": datetime.now().isoformat(),
            }
            self._whitelist_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as error:
            log_warning(self.logger, f"[USBGuard] Falha ao salvar whitelist USB: {error}")
