"""Monitor comportamental para detecção de ameaças em processo de execução."""

from __future__ import annotations

import logging
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from app.core.risk import RiskLevel, ThreatClassification
from app.utils.logger import log_info, log_warning, log_error


@dataclass
class ProcessBehaviorRisk:
    """Resultado da análise comportamental de um processo."""

    process_id: int
    process_name: str
    behavioral_score: int  # 0-100
    risk_level: RiskLevel
    detected_behaviors: list[str]
    injection_attempt: bool = False
    encryption_pattern: bool = False
    av_evasion_attempt: bool = False
    registry_modification_attempt: bool = False
    network_suspicious: bool = False
    explanation: str = ""


class BehaviorMonitor:
    """Monitora comportamento de processos para detectar ameaças em tempo real."""

    # Padrões suspeitos de API calls via Windows
    INJECTION_INDICATORS = {
        "VirtualAllocEx",      # Alocação de memória em processo remoto
        "WriteProcessMemory",  # Escrita em memória de outro processo
        "CreateRemoteThread",  # Criar thread em processo remoto
        "SetWindowsHookEx",    # Hook em mensagens do sistema
        "LoadLibrary",         # Carregar DLL em contexto suspeito
        "ReflectiveInjection",
    }

    ENCRYPTION_INDICATORS = {
        "CryptEncrypt",
        "CryptDecrypt",
        "AES",
        "RSA",
        "ChaCha",
        "EncryptFileA",
        "EncryptFileW",
        "RtlEncryptMemory",
        "multiple file extensions changed",  # Comportamento de ransomware
        "FILE_ATTRIBUTE_HIDDEN",
    }

    AV_EVASION_INDICATORS = {
        "WMI.EventConsumer.Binding",
        "Win32_ProcessStartTrace",
        "AthenaMonitoring",
        "Deny Write Access",
        "Disable Memory Protection",
        "DisableRealtime Scanning",
        "tamper protection",
        "defender",
        "kaspersky",
        "avast",
    }

    REGISTRY_PERSISTENCE_PATTERNS = {
        "\\Run\\",
        "\\RunOnce\\",
        "\\Services\\",
        "CurrentVersion\\Explorer\\Run",
        "CurrentVersion\\Windows\\Load",
        "AppInit_DLLs",
        "Notify",
    }

    SUSPICIOUS_NETWORK_PATTERNS = {
        r"^(127\.|localhost)",  # Loopback (pode ser legítimo)
        r":(53|853|8853)$",      # DNS (legítimo mas pode ser abusado)
        r":(445|139)$",          # SMB (network spread)
        r":443.*proxy",           # HTTPS com indicação de proxy
        r"HTTPS.*C2:",            # Command and Control obvio
        r"dynamic\.dns|dyn\.com", # DynamicDNS (comum em malware)
    }

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    def analyze_process_behavior(self, process_id: int, process_name: str) -> Optional[ProcessBehaviorRisk]:
        """Analisa comportamento de um processo em execução."""
        if not self._is_windows():
            return None

        behaviors = []
        score = 0

        # Analisar injeção
        injection_detected = self._check_injection_pattern(process_id)
        if injection_detected:
            behaviors.append("Injeção de código em processo remoto detectada")
            score += 30

        # Analisar criptografia
        encryption_detected = self._check_encryption_pattern(process_id)
        if encryption_detected:
            behaviors.append("Padrão de criptografia de múltiplos arquivos detectado")
            score += 35

        # Analisar tentativa de evasão de AV
        av_evasion_detected = self._check_av_evasion_attempt(process_id, process_name)
        if av_evasion_detected:
            behaviors.append("Tentativa de desabilitar antivírus detectada")
            score += 40

        # Analisar modificações de registry
        registry_mod_detected = self._check_registry_persistence_attempt(process_id)
        if registry_mod_detected:
            behaviors.append("Tentativa de modificação do registry de inicialização detectada")
            score += 25

        # Analisar conexões de rede
        network_suspicious = self._check_suspicious_network_connections(process_id)
        if network_suspicious:
            behaviors.append("Conexões de rede suspeitas detectadas")
            score += 20

        # Se nenhum comportamento foi detectado, retornar None
        if not behaviors:
            return None

        risk_level = self._score_to_risk_level(score)

        return ProcessBehaviorRisk(
            process_id=process_id,
            process_name=process_name,
            behavioral_score=min(100, score),
            risk_level=risk_level,
            detected_behaviors=behaviors,
            injection_attempt=injection_detected,
            encryption_pattern=encryption_detected,
            av_evasion_attempt=av_evasion_detected,
            registry_modification_attempt=registry_mod_detected,
            network_suspicious=network_suspicious,
            explanation=self._build_behavior_explanation(behaviors, score),
        )

    def _check_injection_pattern(self, process_id: int) -> bool:
        """Verifica sinais de code injection."""
        try:
            # Usar Get-Process no PowerShell para analisar threads e memória
            # Nota: Implementação simplificada; em produção precisaria de WMI/ETW
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$p = Get-Process -Id {process_id} -ErrorAction Ignore; "
                 "$p | Select-Object -ExpandProperty Modules | Where-Object {{$_.FileName -like '*temp*' -or $_.FileName -like '*appdata*'}}"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            return bool(output.stdout.strip())
        except Exception:
            return False

    def _check_encryption_pattern(self, process_id: int) -> bool:
        """Verifica sinais de criptografia de arquivos em massa."""
        try:
            # Procura processos que abrem múltiplos arquivos rapidamente
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-Process -Id {process_id} -ErrorAction Ignore | "
                 "Select-Object -ExpandProperty Modules | Where-Object {{$_.ModuleName -match '(crypto|encrypt|crypt)' -or $_.FileName -match '\\\\temp\\\\|\\\\appdata\\\\'}} | "
                 "Measure-Object | Select-Object -ExpandProperty Count"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            count = int(output.stdout.strip() or "0")
            return count >= 3  # Múltiplos módulos criptográficos carregados
        except Exception:
            return False

    def _check_av_evasion_attempt(self, process_id: int, process_name: str) -> bool:
        """Verifica tentativas de desabilitar AV."""
        try:
            # Procurar por comandos que tentam desabilitar Windows Defender
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$proc = Get-Process -Id {process_id} -ErrorAction Ignore; "
                 "if ($proc) {{ Get-WmiObject Win32_ProcessStartTrace -Filter \\\"ProcessID={process_id}\\\" "
                 "-ErrorAction Ignore | Select-Object -ExpandProperty CommandLine | Where-Object {{$_ -match 'defender|tamper|disable|set-mppe'}} }}"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            
            # Também verificar registry direto
            if "defender" in process_name.lower() or "securitycenter" in process_name.lower():
                return False  # Processos legítimos do Windows
            
            return bool(output.stdout.strip())
        except Exception:
            return False

    def _check_registry_persistence_attempt(self, process_id: int) -> bool:
        """Verifica modificações de registry de inicialização."""
        try:
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*' "
                 "-ErrorAction Ignore | Where-Object {{$_.PSPath -notmatch 'Microsoft|Google|Adobe|Nvidia'}} | Measure-Object | Select-Object -ExpandProperty Count"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            count = int(output.stdout.strip() or "0")
            return count > 2  # Mais que poucas entradas suspeitas de inicialização
        except Exception:
            return False

    def _check_suspicious_network_connections(self, process_id: int) -> bool:
        """Verifica conexões de rede suspeitas."""
        try:
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-NetTCPConnection -OwningProcess {process_id} -State Established "
                 "-ErrorAction Ignore | Where-Object {{$_.RemoteAddress -notmatch '^(10\\.|172\\.|192\\.|127\\.|::1|fe80:)' "
                 " -and $_.RemotePort -notmatch '(443|80|53|22|3389)' }} | Measure-Object | Select-Object -ExpandProperty Count"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            count = int(output.stdout.strip() or "0")
            return count > 0  # Qualquer conexão "estranha"
        except Exception:
            return False

    @staticmethod
    def _is_windows() -> bool:
        """Verifica se está rodando no Windows."""
        import sys
        return sys.platform == "win32"

    @staticmethod
    def _score_to_risk_level(score: int) -> RiskLevel:
        """Converte score em RiskLevel."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    @staticmethod
    def _build_behavior_explanation(behaviors: list[str], score: int) -> str:
        """Cria texto explicativo do risco detectado."""
        if not behaviors:
            return "Sem comportamentos suspeitos detectados"
        
        explanation = f"Comportamentos suspeitos detectados (score: {score}/100):\n"
        for i, behavior in enumerate(behaviors, 1):
            explanation += f"{i}. {behavior}\n"
        
        return explanation.strip()
