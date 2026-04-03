"""Servico de Auditoria Avancada de Seguranca do SentinelaPC.

Realiza checagens tecnicas reais sobre configuracoes do Windows, exposicao
de rede, acesso remoto, protecao de dados e indicadores de privacidade.

Principios deste modulo:
- Apenas exibir alertas com base em evidencia tecnica verificada.
- Retornar AuditStatus.UNKNOWN quando nao for possivel verificar confiavelmente.
- Nao classificar configuracoes inativas como "virus" ou "malware".
- Nao ler senhas, cookies, tokens ou conteudo privado do usuario.
- Checagens que exigem elevacao de privilegio devem falhar graciosamente.
"""

# Adicionado: servico completo de auditoria avancada de seguranca.

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import subprocess
import ctypes
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from app.core.risk import RiskLevel, ThreatClassification
from app.services.browser_scan_models import BrowserScanItem
from app.services.browser_security_service import BrowserSecurityService
from app.services.audit_models import (
    AUDIT_SCORE_THRESHOLD_ATTENTION,
    AUDIT_SCORE_THRESHOLD_CRITICAL,
    AUDIT_SCORE_THRESHOLD_VULNERABLE,
    AuditCategory,
    AuditFinding,
    AuditReport,
    AuditResolutionResult,
    AuditSeverity,
    AuditStatus,
)
from app.services.email_scan_models import EmailScanItem
from app.services.email_security_service import EmailSecurityService
from app.services.file_scanner_service import ScanControl
from app.utils.logger import log_error, log_info, log_warning

# winreg esta disponivel apenas no Windows; o bloco try preserva
# a compatibilidade de importacao em ambientes de desenvolvimento multiplataforma.
try:
    import winreg  # type: ignore[import]
except ImportError:
    winreg = None  # type: ignore[assignment]

# Flag que suprime janelas de console ao executar subprocessos no Windows.
_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class AuditService:
    """Executa a auditoria avancada de seguranca do sistema Windows.

    Cada metodo _check_* realiza uma checagem tecnica independente e retorna
    um ou mais AuditFinding com categoria, severidade, status, score e evidencias.
    Nenhuma checagem produz alertas sem base em dados do sistema.
    """

    def __init__(
        self,
        logger: logging.Logger,
        browser_service: BrowserSecurityService | None = None,
        email_service: EmailSecurityService | None = None,
    ) -> None:
        # Logger recebido do contexto de aplicacao para rastreabilidade
        self._logger = logger
        self._browser_service = browser_service
        self._email_service = email_service

    # ------------------------------------------------------------------
    # Metodo principal de execucao da auditoria
    # ------------------------------------------------------------------

    def run_full_audit(
        self,
        progress_callback: Callable[[str], None] | None = None,
        scan_control: ScanControl | None = None,
    ) -> AuditReport:
        """Executa todas as checagens de auditoria em sequencia e retorna o relatorio.

        O scan_control permite cancelamento cooperativo entre os grupos de checagens.
        Nenhuma checagem individual e interrompida no meio; o cancelamento ocorre
        apenas entre os grupos definidos abaixo.
        """
        findings: list[AuditFinding] = []

        def _progress(msg: str) -> None:
            if progress_callback:
                progress_callback(msg)
            log_info(self._logger, msg)

        def _cancelled() -> bool:
            return scan_control is not None and scan_control.is_cancelled()

        def _finish(interrupted: bool) -> AuditReport:
            total_score, overall_status = self._calculate_score(findings)
            return AuditReport(
                findings=findings,
                total_score=total_score,
                overall_status=overall_status,
                interrupted=interrupted,
            )

        # ------------------------------------------------------------------
        # Grupo 1: Configuracoes de seguranca do sistema Windows
        # ------------------------------------------------------------------
        _progress("[Auditoria] Verificando configuracoes do sistema (DEP, UAC, SmartScreen)...")
        for check_fn in [
            self._check_dep,
            self._check_uac,
            self._check_smartscreen,
            self._check_lock_screen_notifications,
            self._check_blank_password_protection,
            self._check_last_security_update,
        ]:
            if _cancelled():
                return _finish(interrupted=True)
            findings.append(check_fn())

        # ------------------------------------------------------------------
        # Grupo 2: Firewall e protecao em tempo real
        # ------------------------------------------------------------------
        _progress("[Auditoria] Verificando firewall e protecao antivirus...")
        if _cancelled():
            return _finish(interrupted=True)
        findings.append(self._check_defender())
        if _cancelled():
            return _finish(interrupted=True)
        findings.extend(self._check_firewall())

        # ------------------------------------------------------------------
        # Grupo 3: Exposicao de acesso remoto
        # ------------------------------------------------------------------
        _progress("[Auditoria] Verificando acesso remoto (RDP, WinRM, SMBv1)...")
        for check_fn in [
            self._check_rdp,
            self._check_winrm,
            self._check_remote_assistance,
            self._check_smbv1,
        ]:
            if _cancelled():
                return _finish(interrupted=True)
            findings.append(check_fn())

        # ------------------------------------------------------------------
        # Grupo 4: Rede, Wi-Fi e portas expostas
        # ------------------------------------------------------------------
        _progress("[Auditoria] Verificando rede, Wi-Fi e portas escutando...")
        if _cancelled():
            return _finish(interrupted=True)
        findings.extend(self._check_wifi_security())
        if _cancelled():
            return _finish(interrupted=True)
        findings.append(self._check_proxy_settings())
        if _cancelled():
            return _finish(interrupted=True)
        findings.extend(self._check_listening_ports())
        if _cancelled():
            return _finish(interrupted=True)
        findings.append(self._check_dns_security())

        # ------------------------------------------------------------------
        # Grupo 5: Protecao de dados e privacidade
        # ------------------------------------------------------------------
        _progress("[Auditoria] Verificando protecao de dados e privacidade...")
        for check_fn in [
            self._check_bitlocker,
            self._check_controlled_folder_access,
            self._check_browser_credential_files,
            self._check_webcam_privacy,
            self._check_microphone_privacy,
        ]:
            if _cancelled():
                return _finish(interrupted=True)
            findings.append(check_fn())

        # ------------------------------------------------------------------
        # Grupo 6: Navegador e e-mails exportados
        # ------------------------------------------------------------------
        _progress("[Auditoria] Consolidando riscos de navegador e e-mails exportados...")
        if _cancelled():
            return _finish(interrupted=True)
        findings.extend(self._collect_browser_findings(progress_callback, scan_control))
        if _cancelled():
            return _finish(interrupted=True)
        findings.extend(self._collect_email_findings(progress_callback, scan_control))

        report = _finish(interrupted=False)
        _progress(
            f"[Auditoria] Auditoria concluida. "
            f"Score total: {report.total_score} | Status: {report.overall_status.value} | "
            f"Achados: {len(report.findings)}"
        )
        return report

    def resolve_finding(self, finding: AuditFinding) -> AuditResolutionResult:
        """Tenta resolver um achado suportado com automacao segura.

        Apenas configuracoes deterministicas e de baixo risco operacional sao
        alteradas automaticamente. Demais itens retornam orientacao guiada.
        """
        resolver_key = finding.resolver_key
        if not resolver_key:
            return AuditResolutionResult(
                applied=False,
                message="Este achado nao possui acao automatica segura.",
                details=[finding.recommendation or "Use a recomendacao exibida para tratar o item manualmente."],
            )

        requires_admin_keys = {
            "firewall_public_enable",
            "firewall_private_enable",
            "firewall_domain_enable",
            "remote_assistance_disable",
            "rdp_disable",
            "blank_password_remote_restrict",
            "winrm_disable",
            "smb1_disable",
            "controlled_folder_access_enable",
            "dep_enable_optin",
            "uac_enable",
            "uac_prompt_enable",
            "smartscreen_enable",
            "defender_realtime_enable",
            "dns_secure_set",
        }
        restart_likely_keys = {"rdp_disable", "winrm_disable", "smb1_disable", "dep_enable_optin", "uac_enable"}

        needs_admin = resolver_key in requires_admin_keys or resolver_key.startswith("block_inbound_port_")
        if needs_admin and not self._is_running_as_admin():
            return AuditResolutionResult(
                applied=False,
                message="Permissao insuficiente para aplicar esta correcao automatica.",
                details=[
                    "Este item exige privilegios de administrador (UAC).",
                    "Feche o SentinelaPC e execute o aplicativo como administrador.",
                    finding.recommendation or "Aplique manualmente se preferir.",
                ],
                requires_restart=resolver_key in restart_likely_keys,
            )

        try:
            if resolver_key.startswith("block_inbound_port_"):
                port_text = resolver_key.removeprefix("block_inbound_port_").strip()
                if not port_text.isdigit():
                    raise ValueError(f"Resolver de porta invalido: {resolver_key}")
                port = int(port_text)
                self._run_powershell(
                    "New-NetFirewallRule "
                    f"-DisplayName 'SentinelaPC Block Inbound Port {port}' "
                    "-Direction Inbound -Action Block -Protocol TCP "
                    f"-LocalPort {port} -Profile Any -ErrorAction SilentlyContinue | Out-Null",
                    timeout=25,
                )
                return AuditResolutionResult(True, f"Regra de bloqueio criada para a porta TCP {port}.")
            if resolver_key == "firewall_public_enable":
                self._run_powershell("Set-NetFirewallProfile -Profile Public -Enabled True", timeout=20)
                return AuditResolutionResult(True, "Firewall do perfil publico ativado com sucesso.")
            if resolver_key == "firewall_private_enable":
                self._run_powershell("Set-NetFirewallProfile -Profile Private -Enabled True", timeout=20)
                return AuditResolutionResult(True, "Firewall do perfil privado ativado com sucesso.")
            if resolver_key == "firewall_domain_enable":
                self._run_powershell("Set-NetFirewallProfile -Profile Domain -Enabled True", timeout=20)
                return AuditResolutionResult(True, "Firewall do perfil de dominio ativado com sucesso.")
            if resolver_key == "proxy_disable":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
                    "-Name ProxyEnable -Value 0",
                    timeout=20,
                )
                return AuditResolutionResult(True, "Proxy manual desativado nas configuracoes do usuario.")
            if resolver_key == "remote_assistance_disable":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' -Name fAllowToGetHelp -Value 0",
                    timeout=20,
                )
                return AuditResolutionResult(True, "Assistencia Remota desativada com sucesso.")
            if resolver_key == "rdp_disable":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
                    timeout=20,
                )
                return AuditResolutionResult(True, "RDP desativado com sucesso.", requires_restart=True)
            if resolver_key == "lock_screen_notifications_disable":
                self._run_powershell(
                    "New-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications' -Force | Out-Null; "
                    "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications' -Name LockScreenToastEnabled -Value 0",
                    timeout=20,
                )
                return AuditResolutionResult(True, "Notificacoes da tela de bloqueio ocultadas com sucesso.")
            if resolver_key == "blank_password_remote_restrict":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 1",
                    timeout=20,
                )
                return AuditResolutionResult(True, "Restricao para contas sem senha foi aplicada.")
            if resolver_key == "winrm_disable":
                self._run_powershell("Disable-PSRemoting -Force", timeout=30)
                return AuditResolutionResult(True, "WinRM desativado com sucesso.", requires_restart=True)
            if resolver_key == "smb1_disable":
                self._run_powershell("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", timeout=30)
                return AuditResolutionResult(True, "SMBv1 desativado com sucesso.", requires_restart=True)
            if resolver_key == "controlled_folder_access_enable":
                self._run_powershell("Set-MpPreference -EnableControlledFolderAccess Enabled", timeout=30)
                return AuditResolutionResult(True, "Acesso Controlado a Pastas ativado com sucesso.")
            if resolver_key == "dep_enable_optin":
                self._run_powershell("bcdedit /set {current} nx OptIn", timeout=30)
                return AuditResolutionResult(True, "DEP configurada para OptIn com sucesso.", requires_restart=True)
            if resolver_key == "uac_enable":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1; "
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5",
                    timeout=20,
                )
                return AuditResolutionResult(True, "UAC reativado com sucesso.", requires_restart=True)
            if resolver_key == "uac_prompt_enable":
                self._run_powershell(
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5",
                    timeout=20,
                )
                return AuditResolutionResult(True, "Solicitacao de confirmacao do UAC reativada.")
            if resolver_key == "smartscreen_enable":
                self._run_powershell(
                    "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Force | Out-Null; "
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value 'Warn'; "
                    "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Force | Out-Null; "
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name EnableSmartScreen -Value 1",
                    timeout=25,
                )
                return AuditResolutionResult(True, "SmartScreen ativado com sucesso.")
            if resolver_key == "defender_realtime_enable":
                self._run_powershell(
                    "Set-MpPreference -DisableRealtimeMonitoring $false; "
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender' -Name DisableAntiSpyware -Value 0",
                    timeout=30,
                )
                return AuditResolutionResult(True, "Protecao em tempo real do Defender reativada.")
            if resolver_key == "webcam_desktop_apps_restrict":
                # Remove consentimentos de apps Win32 para camera (HKCU, sem admin)
                self._run_powershell(
                    "Remove-Item -Path "
                    "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged' "
                    "-Recurse -Force -ErrorAction SilentlyContinue",
                    timeout=15,
                )
                return AuditResolutionResult(True, "Acesso de aplicativos de desktop a webcam removido.")
            if resolver_key == "microphone_desktop_apps_restrict":
                # Remove consentimentos de apps Win32 para microfone (HKCU, sem admin)
                self._run_powershell(
                    "Remove-Item -Path "
                    "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged' "
                    "-Recurse -Force -ErrorAction SilentlyContinue",
                    timeout=15,
                )
                return AuditResolutionResult(True, "Acesso de aplicativos de desktop ao microfone removido.")
            if resolver_key == "dns_secure_set":
                # Altera DNS de todos os adaptadores ativos para Cloudflare 1.1.1.1 (admin)
                self._run_powershell(
                    "$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }; "
                    "foreach ($a in $adapters) { "
                    "  Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex "
                    "  -ServerAddresses ('1.1.1.1','1.0.0.1') -ErrorAction SilentlyContinue"
                    "}",
                    timeout=25,
                )
                return AuditResolutionResult(True, "DNS alterado para Cloudflare (1.1.1.1) em todos os adaptadores ativos.")
        except Exception as exc:
            log_warning(self._logger, f"Falha ao resolver achado '{finding.problem_name}': {exc}")
            details = [f"Erro: {type(exc).__name__}: {exc}"]
            if not self._is_running_as_admin() and (
                resolver_key in requires_admin_keys or resolver_key.startswith("block_inbound_port_")
            ):
                details.append("Dica: execute o SentinelaPC como administrador para aplicar este tipo de correcao.")
            details.append(finding.recommendation or "Execute a acao manualmente.")
            return AuditResolutionResult(
                applied=False,
                message="Nao foi possivel aplicar a correcao automatica.",
                details=details,
                requires_restart=resolver_key in restart_likely_keys,
            )

        return AuditResolutionResult(
            applied=False,
            message="Este achado exige tratamento manual ou revisao do usuario.",
            details=[finding.recommendation or "Sem recomendacao adicional disponivel."],
        )

    # ------------------------------------------------------------------
    # Grupo 1 — Configuracoes do sistema
    # ------------------------------------------------------------------

    def _check_dep(self) -> AuditFinding:
        """Verifica se a Prevencao de Execucao de Dados (DEP) esta ativa.

        Usa WMI via PowerShell (DataExecutionPrevention_SupportPolicy):
        0=AlwaysOff (inseguro), 1=AlwaysOn, 2=OptIn (padrao), 3=OptOut.
        Nao requer elevacao de privilegio.
        """
        problem_name = "DEP / Prevencao de Execucao de Dados"
        try:
            result = self._run_powershell(
                "(Get-CimInstance -ClassName Win32_OperatingSystem)"
                ".DataExecutionPrevention_SupportPolicy",
                timeout=12,
            )
            policy = result.strip()
            policy_labels = {
                "0": "AlwaysOff (desativada para todos os programas)",
                "1": "AlwaysOn",
                "2": "OptIn (componentes do sistema - padrao Windows)",
                "3": "OptOut (ativa para todos, exceto excluidos explicitamente)",
            }
            label = policy_labels.get(policy, f"Valor desconhecido: {policy!r}")

            if policy == "0":
                # Desativada para todos: risco real de execucao de codigo em areas de dados
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.VULNERABLE,
                    score=25,
                    evidence=[f"DataExecutionPrevention_SupportPolicy = 0: {label}"],
                    recommendation=(
                        "Ative a DEP em: Painel de Controle > Sistema > "
                        "Configuracoes avancadas do sistema > Desempenho > DEP."
                    ),
                    resolver_key="dep_enable_optin",
                    auto_resolvable=True,
                )
            if policy in ("1", "2", "3"):
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=[f"DataExecutionPrevention_SupportPolicy = {policy}: {label}"],
                )
            raise ValueError(f"Valor inesperado: {policy!r}")
        except Exception as exc:
            return _unknown(AuditCategory.SYSTEM_CONFIG, problem_name, exc)

    def _check_uac(self) -> AuditFinding:
        """Verifica se o UAC (Controle de Conta de Usuario) esta ativo e com nivel adequado.

        Leituras de registro:
        - EnableLUA = 0 -> UAC totalmente desativado (risco alto)
        - ConsentPromptBehaviorAdmin = 0 -> sem solicitacao ao elevar admin (risco medio)
        """
        problem_name = "UAC / Controle de Conta de Usuario"
        if winreg is None:
            return _not_windows(AuditCategory.SYSTEM_CONFIG, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            )
            enable_lua = winreg.QueryValueEx(key, "EnableLUA")[0]
            try:
                consent_prompt = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")[0]
            except FileNotFoundError:
                consent_prompt = 5  # Padrao Windows: solicita credenciais
            winreg.CloseKey(key)

            if enable_lua == 0:
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.VULNERABLE,
                    score=20,
                    evidence=["EnableLUA = 0: UAC completamente desativado"],
                    recommendation=(
                        "Reative o UAC em: Painel de Controle > Contas de usuario > "
                        "Alterar configuracoes do Controle de Conta de Usuario."
                    ),
                    resolver_key="uac_enable",
                    auto_resolvable=True,
                )
            if consent_prompt == 0:
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=10,
                    evidence=["ConsentPromptBehaviorAdmin = 0: elevacoes de admin sem confirmacao"],
                    recommendation=(
                        "Configure o UAC para solicitar confirmacao ao elevar permissoes "
                        "(valor recomendado: 5)."
                    ),
                    resolver_key="uac_prompt_enable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.SYSTEM_CONFIG,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=[
                    f"EnableLUA = {enable_lua}",
                    f"ConsentPromptBehaviorAdmin = {consent_prompt}",
                ],
            )
        except Exception as exc:
            return _unknown(AuditCategory.SYSTEM_CONFIG, problem_name, exc)

    def _check_smartscreen(self) -> AuditFinding:
        """Verifica se o SmartScreen do Windows esta ativo.

        Verifica dois locais de registro em ordem de prioridade:
        1. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer (SmartScreenEnabled)
        2. HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System (EnableSmartScreen)
        Se nenhuma chave existir, assume ativo (comportamento padrao do Windows).
        """
        problem_name = "Windows SmartScreen"
        if winreg is None:
            return _not_windows(AuditCategory.SYSTEM_CONFIG, problem_name)

        # Local primario (configuracao por usuario/sistema)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            )
            value = winreg.QueryValueEx(key, "SmartScreenEnabled")[0]
            winreg.CloseKey(key)
            if str(value).lower() in ("off", "0"):
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=20,
                    evidence=[f"SmartScreenEnabled = '{value}': filtro desativado"],
                    recommendation=(
                        "Ative o SmartScreen em: Seguranca do Windows > "
                        "Controle de aplicativos e do navegador."
                    ),
                    resolver_key="smartscreen_enable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.SYSTEM_CONFIG,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=[f"SmartScreenEnabled = '{value}'"],
            )
        except FileNotFoundError:
            pass
        except Exception as exc:
            return _unknown(AuditCategory.SYSTEM_CONFIG, problem_name, exc)

        # Local alternativo (politica de grupo)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\System",
            )
            smart_screen = winreg.QueryValueEx(key, "EnableSmartScreen")[0]
            winreg.CloseKey(key)
            if smart_screen == 0:
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=20,
                    evidence=["EnableSmartScreen = 0 (politica de grupo desativa SmartScreen)"],
                    recommendation="Revise a politica ou ative manualmente o SmartScreen.",
                    resolver_key="smartscreen_enable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.SYSTEM_CONFIG,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=[f"EnableSmartScreen = {smart_screen} (politica de grupo)"],
            )
        except FileNotFoundError:
            pass
        except Exception as exc:
            return _unknown(AuditCategory.SYSTEM_CONFIG, problem_name, exc)

        # Chaves nao encontradas: SmartScreen esta no comportamento padrao (ativo)
        return AuditFinding(
            category=AuditCategory.SYSTEM_CONFIG,
            problem_name=problem_name,
            severity=AuditSeverity.INFORMATIVE,
            status=AuditStatus.SAFE,
            score=0,
            evidence=["Chaves de registro nao encontradas: SmartScreen no comportamento padrao (ativo)"],
        )

    def _check_lock_screen_notifications(self) -> AuditFinding:
        """Verifica se notificacoes aparecem na tela de bloqueio.

        LockScreenToastEnabled = 1 (padrao) significa que mensagens aparecem
        na tela bloqueada, potencialmente exibindo informacoes sensiveis.
        """
        problem_name = "Notificacoes visiveis na tela de bloqueio"
        if winreg is None:
            return _not_windows(AuditCategory.PRIVACY, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications",
            )
            try:
                lock_screen_toast = winreg.QueryValueEx(key, "LockScreenToastEnabled")[0]
            except FileNotFoundError:
                lock_screen_toast = 1  # Padrao Windows: habilitado
            winreg.CloseKey(key)

            if lock_screen_toast != 0:
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.LOW,
                    status=AuditStatus.ATTENTION,
                    score=10,
                    evidence=["LockScreenToastEnabled = 1: notificacoes visiveis sem desbloquear"],
                    recommendation=(
                        "Para ocultar notificacoes na tela bloqueada: "
                        "Configuracoes > Sistema > Notificacoes > "
                        "desmarcar 'Mostrar notificacoes na tela de bloqueio'."
                    ),
                    resolver_key="lock_screen_notifications_disable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.PRIVACY,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["LockScreenToastEnabled = 0: notificacoes ocultas na tela de bloqueio"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.PRIVACY, problem_name, exc)

    def _check_blank_password_protection(self) -> AuditFinding:
        """Verifica se contas sem senha podem ser usadas para acesso remoto.

        LimitBlankPasswordUse = 1 (seguro) impede acesso remoto com senha em branco.
        LimitBlankPasswordUse = 0 permite acesso remoto sem senha.
        """
        problem_name = "Protecao contra contas sem senha"
        if winreg is None:
            return _not_windows(AuditCategory.PRIVACY, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa",
            )
            try:
                limit_blank = winreg.QueryValueEx(key, "LimitBlankPasswordUse")[0]
            except FileNotFoundError:
                limit_blank = 1  # Padrao seguro
            winreg.CloseKey(key)

            if limit_blank == 0:
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=["LimitBlankPasswordUse = 0: acesso remoto com conta sem senha permitido"],
                    recommendation=(
                        "Defina senhas em todas as contas locais ou reative a restricao "
                        "via Politica de Seguranca Local > Opcoes de seguranca."
                    ),
                    resolver_key="blank_password_remote_restrict",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.PRIVACY,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["LimitBlankPasswordUse = 1: uso de contas sem senha limitado ao login local"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.PRIVACY, problem_name, exc)

    def _check_last_security_update(self) -> AuditFinding:
        """Verifica quando foi a ultima atualizacao de seguranca instalada.

        Usa Get-HotFix via PowerShell. Se a data mais recente for maior que
        90 dias, retorna Atencao. Caso nao seja possivel parsear a data,
        retorna UNKNOWN em vez de alarme falso.
        """
        problem_name = "Atualizacoes de seguranca recentes"
        try:
            raw = self._run_powershell(
                "Get-HotFix | Sort-Object {"
                "  try { [datetime]$_.InstalledOn } catch { [datetime]::MinValue }"
                "} -Descending | Select-Object -First 1 -Property HotFixID,InstalledOn"
                " | ConvertTo-Json",
                timeout=20,
            )
            if not raw.strip():
                raise ValueError("Saida vazia de Get-HotFix")
            data = json.loads(raw)
            hotfix_id = data.get("HotFixID", "Desconhecido")
            installed_raw = str(data.get("InstalledOn", ""))

            installed_date = _parse_wmi_date(installed_raw)
            if installed_date is None:
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details=f"Ultima atualizacao identificada: {hotfix_id} (data nao parseavel: {installed_raw!r})",
                )

            days_since = (datetime.now() - installed_date).days
            if days_since > 90:
                return AuditFinding(
                    category=AuditCategory.SYSTEM_CONFIG,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=[
                        f"Ultima atualizacao: {hotfix_id}",
                        f"Instalada em: {installed_date.strftime('%d/%m/%Y')} ({days_since} dias atras)",
                    ],
                    recommendation=(
                        "Verifique atualizacoes pendentes em: "
                        "Configuracoes > Windows Update > Verificar atualizacoes."
                    ),
                )
            return AuditFinding(
                category=AuditCategory.SYSTEM_CONFIG,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=[
                    f"Ultima atualizacao: {hotfix_id}",
                    f"Instalada em: {installed_date.strftime('%d/%m/%Y')} ({days_since} dias atras)",
                ],
            )
        except Exception as exc:
            return _unknown(AuditCategory.SYSTEM_CONFIG, problem_name, exc)

    # ------------------------------------------------------------------
    # Grupo 2 — Firewall e protecao em tempo real
    # ------------------------------------------------------------------

    def _check_defender(self) -> AuditFinding:
        """Verifica se ha protecao antivirus ativa registrada no sistema.

        Consulta o namespace WMI SecurityCenter2 (nao requer elevacao).
        Se nenhum produto for encontrado, tenta o registro do Defender
        como fallback. Nao conclui que o sistema esta infectado; apenas
        indica se ha protecao registrada.
        """
        problem_name = "Protecao em tempo real / Antivirus"
        # Tentativa 1: SecurityCenter2 (lista qualquer AV registrado, incluindo terceiros)
        try:
            raw = self._run_powershell(
                "Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct"
                " | Select-Object displayName,productState | ConvertTo-Json",
                timeout=15,
            )
            if raw.strip():
                products = json.loads(raw)
                if isinstance(products, dict):
                    products = [products]
                if products:
                    names = [p.get("displayName", "Desconhecido") for p in products]
                    return AuditFinding(
                        category=AuditCategory.MALWARE,
                        problem_name=problem_name,
                        severity=AuditSeverity.INFORMATIVE,
                        status=AuditStatus.SAFE,
                        score=0,
                        evidence=[f"Antivirus registrado no SecurityCenter2: {', '.join(names)}"],
                    )
        except Exception:
            pass

        # Tentativa 2: Registro do Windows Defender
        if winreg is not None:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender",
                )
                try:
                    disable_av = winreg.QueryValueEx(key, "DisableAntiSpyware")[0]
                except FileNotFoundError:
                    disable_av = 0  # Chave ausente = nao desativado via registro
                winreg.CloseKey(key)

                if disable_av == 1:
                    return AuditFinding(
                        category=AuditCategory.MALWARE,
                        problem_name=problem_name,
                        severity=AuditSeverity.CRITICAL,
                        status=AuditStatus.CRITICAL,
                        score=35,
                        evidence=["DisableAntiSpyware = 1: Windows Defender desativado via registro"],
                        recommendation=(
                            "Reative o Windows Defender ou instale um antivirus alternativo. "
                            "Sem protecao em tempo real, o sistema esta vulneravel a malware."
                        ),
                        resolver_key="defender_realtime_enable",
                        auto_resolvable=True,
                    )
                return AuditFinding(
                    category=AuditCategory.MALWARE,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Windows Defender: chave DisableAntiSpyware = 0 (nao desativado via registro)"],
                )
            except Exception:
                pass

        return AuditFinding(
            category=AuditCategory.MALWARE,
            problem_name=problem_name,
            severity=AuditSeverity.INFORMATIVE,
            status=AuditStatus.UNKNOWN,
            score=0,
            details="Nao foi possivel verificar o status da protecao em tempo real",
        )

    def _check_firewall(self) -> list[AuditFinding]:
        """Verifica o status do Firewall do Windows nos 3 perfis de rede.

        Usa Get-NetFirewallProfile via PowerShell. Cada perfil (Dominio,
        Privado, Publico) gera um achado separado. O perfil Publico
        desativado recebe score mais alto por ser de maior risco.
        """
        findings: list[AuditFinding] = []
        try:
            raw = self._run_powershell(
                "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json",
                timeout=12,
            )
            profiles = json.loads(raw)
            if isinstance(profiles, dict):
                profiles = [profiles]

            # Pesos por perfil: Publico tem o maior impacto em redes desconhecidas
            profile_pt = {"Domain": "Dominio", "Private": "Privado", "Public": "Publico"}
            profile_score = {"Domain": 15, "Private": 25, "Public": 40}

            for profile in profiles:
                name = str(profile.get("Name", ""))
                enabled = bool(profile.get("Enabled", True))
                pt_name = profile_pt.get(name, name)
                score = profile_score.get(name, 20)

                if not enabled:
                    findings.append(
                        AuditFinding(
                            category=AuditCategory.FIREWALL,
                            problem_name=f"Firewall desativado - perfil {pt_name}",
                            severity=AuditSeverity.CRITICAL if name == "Public" else AuditSeverity.HIGH,
                            status=AuditStatus.CRITICAL if name == "Public" else AuditStatus.VULNERABLE,
                            score=score,
                            evidence=[f"Perfil '{pt_name}': firewall desativado"],
                            recommendation=(
                                f"Ative o firewall para o perfil {pt_name} em: "
                                "Seguranca do Windows > Firewall e protecao de rede."
                            ),
                            resolver_key=(
                                "firewall_public_enable" if name == "Public" else
                                "firewall_private_enable" if name == "Private" else
                                "firewall_domain_enable"
                            ),
                            auto_resolvable=True,
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            category=AuditCategory.FIREWALL,
                            problem_name=f"Firewall - perfil {pt_name}",
                            severity=AuditSeverity.INFORMATIVE,
                            status=AuditStatus.SAFE,
                            score=0,
                            evidence=[f"Perfil '{pt_name}': ativo"],
                        )
                    )
        except Exception as exc:
            findings.append(
                AuditFinding(
                    category=AuditCategory.FIREWALL,
                    problem_name="Status do Firewall do Windows",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details=f"Nao foi possivel verificar: {exc}",
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Grupo 3 — Acesso remoto
    # ------------------------------------------------------------------

    def _check_rdp(self) -> AuditFinding:
        """Verifica se o Remote Desktop Protocol (RDP) esta ativo.

        fDenyTSConnections = 0 significa que RDP esta ativo.
        Tambem verifica se NLA (UserAuthentication) esta habilitado,
        o que reduz o risco de conexoes sem pre-autenticacao.
        """
        problem_name = "Remote Desktop Protocol (RDP)"
        if winreg is None:
            return _not_windows(AuditCategory.REMOTE_ACCESS, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            )
            deny_ts = winreg.QueryValueEx(key, "fDenyTSConnections")[0]
            winreg.CloseKey(key)

            if deny_ts != 0:
                return AuditFinding(
                    category=AuditCategory.REMOTE_ACCESS,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["fDenyTSConnections = 1: RDP desativado"],
                )

            # RDP ativo: verificar NLA
            nla_required = 1
            try:
                nla_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                )
                nla_required = winreg.QueryValueEx(nla_key, "UserAuthentication")[0]
                winreg.CloseKey(nla_key)
            except Exception:
                pass

            evidence = ["fDenyTSConnections = 0: RDP esta ativo"]
            if nla_required == 1:
                evidence.append("NLA (Autenticacao no nivel da rede) ativo: risco reduzido")
                score = 15
                severity = AuditSeverity.MEDIUM
                status = AuditStatus.ATTENTION
            else:
                evidence.append("NLA desativado: conexoes sem pre-autenticacao sao aceitas")
                score = 30
                severity = AuditSeverity.HIGH
                status = AuditStatus.VULNERABLE

            return AuditFinding(
                category=AuditCategory.REMOTE_ACCESS,
                problem_name=problem_name,
                severity=severity,
                status=status,
                score=score,
                evidence=evidence,
                recommendation=(
                    "Se o RDP nao for necessario, desative em: "
                    "Configuracoes > Sistema > Area de Trabalho Remota. "
                    "Se precisar manter, garanta NLA ativo e use senha forte."
                ),
                resolver_key="rdp_disable",
                auto_resolvable=True,
            )
        except Exception as exc:
            return _unknown(AuditCategory.REMOTE_ACCESS, problem_name, exc)

    def _check_winrm(self) -> AuditFinding:
        """Verifica se o servico WinRM (Windows Remote Management) esta em execucao.

        WinRM ativo expoe o sistema a gerenciamento remoto via PowerShell Remoting.
        Nao eh necessariamente malicioso, mas deve ser revisado se nao for usado.
        """
        problem_name = "WinRM / Gerenciamento remoto do Windows"
        try:
            result = subprocess.run(
                ["sc", "query", "WinRM"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=_CREATE_NO_WINDOW,
            )
            if "RUNNING" in result.stdout:
                return AuditFinding(
                    category=AuditCategory.REMOTE_ACCESS,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=20,
                    evidence=["Servico WinRM: em execucao (RUNNING)"],
                    recommendation=(
                        "Se o gerenciamento remoto nao for necessario, desative com: "
                        "'Disable-PSRemoting -Force' no PowerShell como administrador."
                    ),
                    resolver_key="winrm_disable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.REMOTE_ACCESS,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["Servico WinRM: nao esta em execucao"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.REMOTE_ACCESS, problem_name, exc)

    def _check_remote_assistance(self) -> AuditFinding:
        """Verifica se a Assistencia Remota do Windows esta habilitada.

        fAllowToGetHelp = 1 permite que outro usuario assuma o controle
        mediante solicitacao. Geralmente e seguro, mas pode ser desativado
        se nao for usado regularmente.
        """
        problem_name = "Assistencia Remota do Windows"
        if winreg is None:
            return _not_windows(AuditCategory.REMOTE_ACCESS, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            )
            allow_help = winreg.QueryValueEx(key, "fAllowToGetHelp")[0]
            winreg.CloseKey(key)

            if allow_help == 1:
                return AuditFinding(
                    category=AuditCategory.REMOTE_ACCESS,
                    problem_name=problem_name,
                    severity=AuditSeverity.LOW,
                    status=AuditStatus.ATTENTION,
                    score=10,
                    evidence=["fAllowToGetHelp = 1: Assistencia Remota habilitada"],
                    recommendation=(
                        "Se nao precisar de suporte remoto, desative em: "
                        "Propriedades do Sistema > Acesso Remoto > "
                        "desmarcar 'Permitir conexoes de Assistencia Remota'."
                    ),
                    resolver_key="remote_assistance_disable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.REMOTE_ACCESS,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["fAllowToGetHelp = 0: Assistencia Remota desativada"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.REMOTE_ACCESS, problem_name, exc)

    def _check_smbv1(self) -> AuditFinding:
        """Verifica se o protocolo SMBv1 esta ativo.

        SMBv1 e o protocolo explorado pelo WannaCry/EternalBlue.
        Tenta PowerShell (Get-SmbServerConfiguration) e como fallback
        verifica a chave de registro LanmanServer\\Parameters\\SMB1.
        """
        problem_name = "Protocolo SMBv1 (WannaCry / EternalBlue)"

        # Tentativa 1: PowerShell Get-SmbServerConfiguration
        try:
            raw = self._run_powershell(
                "(Get-SmbServerConfiguration).EnableSMB1Protocol",
                timeout=12,
            )
            value = raw.strip().lower()
            if value == "true":
                return AuditFinding(
                    category=AuditCategory.REMOTE_ACCESS,
                    problem_name=problem_name,
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.VULNERABLE,
                    score=25,
                    evidence=["EnableSMB1Protocol = True (Get-SmbServerConfiguration)"],
                    recommendation=(
                        "Desative com: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' "
                        "no PowerShell como administrador."
                    ),
                    resolver_key="smb1_disable",
                    auto_resolvable=True,
                )
            if value == "false":
                return AuditFinding(
                    category=AuditCategory.REMOTE_ACCESS,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["EnableSMB1Protocol = False (Get-SmbServerConfiguration)"],
                )
        except Exception:
            pass

        # Tentativa 2: Registro (fallback para sistemas sem Get-SmbServerConfiguration)
        if winreg is not None:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                )
                try:
                    smb1 = winreg.QueryValueEx(key, "SMB1")[0]
                except FileNotFoundError:
                    smb1 = None
                winreg.CloseKey(key)

                if smb1 == 1:
                    return AuditFinding(
                        category=AuditCategory.REMOTE_ACCESS,
                        problem_name=problem_name,
                        severity=AuditSeverity.HIGH,
                        status=AuditStatus.VULNERABLE,
                        score=25,
                        evidence=["LanmanServer\\Parameters\\SMB1 = 1 (registro)"],
                        recommendation=(
                            "Desative: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'."
                        ),
                        resolver_key="smb1_disable",
                        auto_resolvable=True,
                    )
                if smb1 == 0:
                    return AuditFinding(
                        category=AuditCategory.REMOTE_ACCESS,
                        problem_name=problem_name,
                        severity=AuditSeverity.INFORMATIVE,
                        status=AuditStatus.SAFE,
                        score=0,
                        evidence=["LanmanServer\\Parameters\\SMB1 = 0 (registro: desativado)"],
                    )
            except Exception:
                pass

        return AuditFinding(
            category=AuditCategory.REMOTE_ACCESS,
            problem_name=problem_name,
            severity=AuditSeverity.INFORMATIVE,
            status=AuditStatus.UNKNOWN,
            score=0,
            details="Nao foi possivel verificar o status do SMBv1",
        )

    # ------------------------------------------------------------------
    # Grupo 4 — Rede, Wi-Fi e portas expostas
    # ------------------------------------------------------------------

    def _check_wifi_security(self) -> list[AuditFinding]:
        """Verifica o tipo de seguranca da rede Wi-Fi atual via netsh wlan.

        Detecta redes abertas (sem senha) e redes com WEP (criptografia
        vulneravel). WPA2/WPA3 e considerado adequado.
        Se nao houver interface Wi-Fi, retorna um achado Seguro.
        """
        findings: list[AuditFinding] = []
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = result.stdout

            if "There is no wireless interface" in output or not output.strip():
                return [
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Seguranca da rede Wi-Fi",
                        severity=AuditSeverity.INFORMATIVE,
                        status=AuditStatus.SAFE,
                        score=0,
                        evidence=["Nenhuma interface Wi-Fi detectada"],
                    )
                ]

            auth_match = re.search(r"Authentication\s*:\s*(.+)", output, re.IGNORECASE)
            cipher_match = re.search(r"Cipher\s*:\s*(.+)", output, re.IGNORECASE)
            ssid_match = re.search(r"^\s+SSID\s*:\s*(.+)", output, re.IGNORECASE | re.MULTILINE)

            if not auth_match:
                return [
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Seguranca da rede Wi-Fi",
                        severity=AuditSeverity.INFORMATIVE,
                        status=AuditStatus.UNKNOWN,
                        score=0,
                        details="Interface Wi-Fi detectada mas nao conectada ou sem dados de autenticacao",
                    )
                ]

            auth = auth_match.group(1).strip()
            cipher = cipher_match.group(1).strip() if cipher_match else "Desconhecido"
            ssid = ssid_match.group(1).strip() if ssid_match else "Rede atual"
            evidence_base = [f"SSID: {ssid}", f"Autenticacao: {auth}", f"Cipher: {cipher}"]

            auth_upper = auth.upper()
            if auth.lower() in ("open", "none", ""):
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Rede Wi-Fi sem protecao (aberta)",
                        severity=AuditSeverity.CRITICAL,
                        status=AuditStatus.CRITICAL,
                        score=30,
                        evidence=evidence_base,
                        recommendation=(
                            "Evite transmitir dados sensiveis em redes abertas. "
                            "Use uma VPN para proteger o trafego."
                        ),
                    )
                )
            elif "WEP" in auth_upper:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Rede Wi-Fi com criptografia WEP (vulneravel)",
                        severity=AuditSeverity.HIGH,
                        status=AuditStatus.VULNERABLE,
                        score=25,
                        evidence=evidence_base,
                        recommendation="Atualize o roteador para usar WPA2 ou WPA3. O WEP pode ser quebrado em segundos.",
                    )
                )
            elif "WPA2" in auth_upper or "WPA3" in auth_upper:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Seguranca da rede Wi-Fi",
                        severity=AuditSeverity.INFORMATIVE,
                        status=AuditStatus.SAFE,
                        score=0,
                        evidence=evidence_base,
                    )
                )
            else:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name="Seguranca da rede Wi-Fi",
                        severity=AuditSeverity.LOW,
                        status=AuditStatus.ATTENTION,
                        score=10,
                        evidence=evidence_base,
                        recommendation="Verifique se a rede usa WPA2 ou superior.",
                    )
                )
        except Exception as exc:
            findings.append(_unknown(AuditCategory.NETWORK, "Seguranca da rede Wi-Fi", exc))
        return findings

    def _check_proxy_settings(self) -> AuditFinding:
        """Verifica se um proxy esta configurado no Internet Explorer / sistema.

        Um proxy desconhecido pode interceptar o trafego HTTP/HTTPS.
        Esta checagem apenas informa que um proxy existe; nao classifica
        automaticamente como malicioso.
        """
        problem_name = "Proxy de sistema configurado"
        if winreg is None:
            return _not_windows(AuditCategory.NETWORK, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            try:
                proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                proxy_enable = 0
            proxy_server = ""
            if proxy_enable:
                try:
                    proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)

            if proxy_enable and proxy_server:
                return AuditFinding(
                    category=AuditCategory.NETWORK,
                    problem_name=problem_name,
                    severity=AuditSeverity.LOW,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=[
                        f"Proxy ativo: {proxy_server}",
                        "Todo trafego de navegacao passa por este servidor",
                    ],
                    recommendation=(
                        "Verifique se este proxy foi configurado por voce ou por software autorizado. "
                        "Proxies desconhecidos podem interceptar dados de navegacao."
                    ),
                    resolver_key="proxy_disable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.NETWORK,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["Nenhum proxy manual ativo nas configuracoes de Internet"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.NETWORK, problem_name, exc)

    def _check_listening_ports(self) -> list[AuditFinding]:
        """Identifica portas sensiveis escutando em interfaces nao-loopback.

        Usa psutil.net_connections(). Nao analisa portas ja cobertas pelos
        checks de RDP, WinRM e SMB neste servico (evitar duplicidade).
        Portas classicamente usadas por backdoors recebem score Critico.
        """
        # Portas classicas de backdoor/RAT: score critico
        BACKDOOR_PORTS = {4444, 31337, 1234, 12345, 65535, 6666, 7777}
        # Servicos nao criptografados de alto risco
        INSECURE_SERVICES = {21: "FTP", 23: "Telnet", 513: "rlogin", 514: "rsh/rexec"}
        # Protocolos legados com exposicao de rede
        LEGACY_SERVICES = {135: "RPC Endpoint Mapper", 139: "NetBIOS Session", 445: "SMB"}

        findings: list[AuditFinding] = []
        try:
            connections = psutil.net_connections(kind="tcp")
        except Exception as exc:
            return [_unknown(AuditCategory.NETWORK, "Portas locais em escuta externa", exc)]

        external: dict[int, str] = {}
        for conn in connections:
            if conn.status != "LISTEN" or conn.laddr is None:
                continue
            ip = conn.laddr.ip
            # Ignorar loopback (127.x.x.x, ::1) — apenas interfaces externas/all
            if ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1"):
                continue
            external[conn.laddr.port] = ip

        for port in BACKDOOR_PORTS:
            if port in external:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name=f"Porta de risco critico em escuta: {port}",
                        severity=AuditSeverity.CRITICAL,
                        status=AuditStatus.CRITICAL,
                        score=40,
                        evidence=[
                            f"Porta {port} escutando em {external[port]}",
                            "Esta porta e comumente usada por backdoors e ferramentas RAT",
                        ],
                        recommendation=(
                            f"Identifique o processo que usa a porta {port} "
                            "(ex.: 'netstat -b -n | findstr {port}') e encerre se nao reconhecido."
                        ),
                        resolver_key=f"block_inbound_port_{port}",
                        auto_resolvable=True,
                    )
                )

        for port, service in INSECURE_SERVICES.items():
            if port in external:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name=f"Servico inseguro exposto: {service} (porta {port})",
                        severity=AuditSeverity.HIGH,
                        status=AuditStatus.VULNERABLE,
                        score=20,
                        evidence=[f"Porta {port} ({service}) escutando em {external[port]}"],
                        recommendation=f"Desative o servico {service}; transmite dados sem criptografia.",
                        resolver_key=f"block_inbound_port_{port}",
                        auto_resolvable=True,
                    )
                )

        for port, service in LEGACY_SERVICES.items():
            if port in external:
                findings.append(
                    AuditFinding(
                        category=AuditCategory.NETWORK,
                        problem_name=f"Protocolo de rede legado exposto: {service} (porta {port})",
                        severity=AuditSeverity.MEDIUM,
                        status=AuditStatus.ATTENTION,
                        score=10,
                        evidence=[f"Porta {port} ({service}) escutando em {external[port]}"],
                        recommendation=f"Verifique a necessidade de expor {service} em interfaces externas.",
                        resolver_key=f"block_inbound_port_{port}",
                        auto_resolvable=True,
                    )
                )

        if not findings:
            findings.append(
                AuditFinding(
                    category=AuditCategory.NETWORK,
                    problem_name="Portas sensiveis em escuta externa",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Nenhuma porta classicamente critica exposta em interfaces externas"],
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Grupo 5 — Protecao de dados e privacidade
    # ------------------------------------------------------------------

    def _check_bitlocker(self) -> AuditFinding:
        """Verifica o status do BitLocker no disco do sistema.

        Usa Get-BitLockerVolume via PowerShell. Em caso de ausencia de
        privilegios ou BitLocker nao disponivel, retorna UNKNOWN.
        A ausencia de criptografia e apenas ATTENTION, nao CRITICO,
        pois e um recurso opcional com impacto em caso de acesso fisico.
        """
        problem_name = "Criptografia de disco (BitLocker)"
        try:
            raw = self._run_powershell(
                "try {"
                "  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop;"
                "  $v.VolumeStatus"
                "} catch { 'NaoDisponivel' }",
                timeout=15,
            )
            status = raw.strip()

            if status in ("FullyEncrypted", "EncryptionInProgress"):
                return AuditFinding(
                    category=AuditCategory.DATA_PROTECTION,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=[f"BitLocker status: {status} no disco do sistema"],
                )
            if status in ("FullyDecrypted", "NotEncrypted", ""):
                return AuditFinding(
                    category=AuditCategory.DATA_PROTECTION,
                    problem_name=problem_name,
                    severity=AuditSeverity.LOW,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=["Disco do sistema sem criptografia BitLocker"],
                    recommendation=(
                        "O BitLocker protege dados em caso de roubo ou acesso fisico. "
                        "Ative em: Painel de Controle > BitLocker Drive Encryption."
                    ),
                )
            if status == "NaoDisponivel":
                return AuditFinding(
                    category=AuditCategory.DATA_PROTECTION,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details="BitLocker nao disponivel ou verificacao requer privilegios de administrador",
                )
            # Status inesperado (ex.: EncryptionSuspended, DecryptionInProgress)
            return AuditFinding(
                category=AuditCategory.DATA_PROTECTION,
                problem_name=problem_name,
                severity=AuditSeverity.LOW,
                status=AuditStatus.ATTENTION,
                score=15,
                evidence=[f"BitLocker status: '{status}'"],
                recommendation="Verifique o status em: Painel de Controle > BitLocker Drive Encryption.",
            )
        except Exception as exc:
            return _unknown(AuditCategory.DATA_PROTECTION, problem_name, exc)

    def _check_controlled_folder_access(self) -> AuditFinding:
        """Verifica se o Acesso Controlado a Pastas (protecao anti-ransomware) esta ativo.

        EnableControlledFolderAccess:
        0 = desativado, 1 = ativo, 2 = modo auditoria (registra mas nao bloqueia).
        """
        problem_name = "Acesso Controlado a Pastas (protecao anti-ransomware)"
        if winreg is None:
            return _not_windows(AuditCategory.DATA_PROTECTION, problem_name)
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
            )
            enabled = winreg.QueryValueEx(key, "EnableControlledFolderAccess")[0]
            winreg.CloseKey(key)

            if enabled == 0:
                return AuditFinding(
                    category=AuditCategory.DATA_PROTECTION,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=["EnableControlledFolderAccess = 0: protecao desativada"],
                    recommendation=(
                        "Ative em: Seguranca do Windows > Protecao contra virus e ameacas > "
                        "Gerenciar protecao contra ransomware > Acesso controlado a pastas."
                    ),
                    resolver_key="controlled_folder_access_enable",
                    auto_resolvable=True,
                )
            if enabled == 2:
                return AuditFinding(
                    category=AuditCategory.DATA_PROTECTION,
                    problem_name=problem_name,
                    severity=AuditSeverity.LOW,
                    status=AuditStatus.ATTENTION,
                    score=5,
                    evidence=["EnableControlledFolderAccess = 2: modo auditoria (registra, nao bloqueia)"],
                    recommendation="Mude para o modo ativo (1) para protecao real.",
                    resolver_key="controlled_folder_access_enable",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.DATA_PROTECTION,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["EnableControlledFolderAccess = 1: protecao ativa"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.DATA_PROTECTION, problem_name, exc)

    def _check_browser_credential_files(self) -> AuditFinding:
        """Verifica indicadores estruturais de credenciais armazenadas em navegadores.

        Verifica apenas a existencia dos arquivos de banco de senhas.
        Nao le, decripta ou exibe qualquer senha ou dado privado.
        """
        problem_name = "Credenciais armazenadas localmente em navegadores"
        browsers_found: list[str] = []
        local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
        app_data = Path(os.environ.get("APPDATA", ""))

        # Chrome
        if (local_app_data / "Google" / "Chrome" / "User Data" / "Default" / "Login Data").exists():
            browsers_found.append("Google Chrome")
        # Edge
        if (local_app_data / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data").exists():
            browsers_found.append("Microsoft Edge")
        # Firefox
        firefox_profiles = app_data / "Mozilla" / "Firefox" / "Profiles"
        if firefox_profiles.exists():
            for profile_dir in firefox_profiles.iterdir():
                if profile_dir.is_dir() and (profile_dir / "logins.json").exists():
                    browsers_found.append("Mozilla Firefox")
                    break
        # Opera
        if (app_data / "Opera Software" / "Opera Stable" / "Login Data").exists():
            browsers_found.append("Opera")
        # Opera GX
        if (app_data / "Opera Software" / "Opera GX Stable" / "Login Data").exists():
            browsers_found.append("Opera GX")
        # Brave
        if (local_app_data / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Login Data").exists():
            browsers_found.append("Brave")

        if browsers_found:
            return AuditFinding(
                category=AuditCategory.PRIVACY,
                problem_name=problem_name,
                severity=AuditSeverity.LOW,
                status=AuditStatus.ATTENTION,
                score=10,
                evidence=[
                    f"Arquivo de credenciais encontrado em: {', '.join(browsers_found)}",
                    "Nota: apenas a existencia do arquivo foi verificada; nenhuma senha foi lida",
                ],
                recommendation=(
                    "O armazenamento de senhas no navegador e conveniente mas menos seguro "
                    "do que gerenciadores dedicados (ex.: Bitwarden, KeePass). "
                    "Ative a sincronizacao protegida por senha master se disponivel."
                ),
            )
        return AuditFinding(
            category=AuditCategory.PRIVACY,
            problem_name=problem_name,
            severity=AuditSeverity.INFORMATIVE,
            status=AuditStatus.SAFE,
            score=0,
            evidence=["Nenhum arquivo de credenciais detectado nos perfis de navegadores verificados"],
        )

    def _check_webcam_privacy(self) -> AuditFinding:
        """Verifica se aplicativos de desktop tem acesso concedido a webcam do sistema.

        Consulta o ConsentStore de camera (HKCU) sem precisar de elevacao.
        Presenca da chave NonPackaged com subentradas indica que apps Win32 receberam acesso.
        """
        problem_name = "Acesso de aplicativos a webcam"
        if winreg is None:
            return _not_windows(AuditCategory.PRIVACY, problem_name)
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            try:
                global_value = winreg.QueryValueEx(key, "Value")[0]
            except FileNotFoundError:
                global_value = "Allow"
            winreg.CloseKey(key)

            if str(global_value).lower() == "deny":
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Acesso global a webcam: bloqueado para todos os aplicativos"],
                )

            nonpackaged_apps: list[str] = []
            try:
                np_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path + r"\NonPackaged")
                idx = 0
                while True:
                    try:
                        nonpackaged_apps.append(winreg.EnumKey(np_key, idx))
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(np_key)
            except FileNotFoundError:
                pass

            if nonpackaged_apps:
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=[
                        f"{len(nonpackaged_apps)} aplicativo(s) de desktop com acesso concedido a webcam",
                        *[f"App: {a[:80]}" for a in nonpackaged_apps[:5]],
                    ],
                    recommendation=(
                        "Revise quais aplicativos precisam de camera em: "
                        "Configuracoes > Privacidade e seguranca > Camera. "
                        "Remova o acesso de apps que nao reconhece."
                    ),
                    resolver_key="webcam_desktop_apps_restrict",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.PRIVACY,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["Nenhum aplicativo de desktop registrado com acesso a webcam"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.PRIVACY, problem_name, exc)

    def _check_microphone_privacy(self) -> AuditFinding:
        """Verifica se aplicativos de desktop tem acesso concedido ao microfone do sistema.

        Consulta o ConsentStore de microfone (HKCU) sem precisar de elevacao.
        """
        problem_name = "Acesso de aplicativos ao microfone"
        if winreg is None:
            return _not_windows(AuditCategory.PRIVACY, problem_name)
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            try:
                global_value = winreg.QueryValueEx(key, "Value")[0]
            except FileNotFoundError:
                global_value = "Allow"
            winreg.CloseKey(key)

            if str(global_value).lower() == "deny":
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Acesso global ao microfone: bloqueado para todos os aplicativos"],
                )

            nonpackaged_apps: list[str] = []
            try:
                np_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path + r"\NonPackaged")
                idx = 0
                while True:
                    try:
                        nonpackaged_apps.append(winreg.EnumKey(np_key, idx))
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(np_key)
            except FileNotFoundError:
                pass

            if nonpackaged_apps:
                return AuditFinding(
                    category=AuditCategory.PRIVACY,
                    problem_name=problem_name,
                    severity=AuditSeverity.MEDIUM,
                    status=AuditStatus.ATTENTION,
                    score=15,
                    evidence=[
                        f"{len(nonpackaged_apps)} aplicativo(s) de desktop com acesso concedido ao microfone",
                        *[f"App: {a[:80]}" for a in nonpackaged_apps[:5]],
                    ],
                    recommendation=(
                        "Revise quais aplicativos precisam de microfone em: "
                        "Configuracoes > Privacidade e seguranca > Microfone. "
                        "Remova o acesso de apps que nao reconhece."
                    ),
                    resolver_key="microphone_desktop_apps_restrict",
                    auto_resolvable=True,
                )
            return AuditFinding(
                category=AuditCategory.PRIVACY,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=["Nenhum aplicativo de desktop registrado com acesso ao microfone"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.PRIVACY, problem_name, exc)

    def _check_dns_security(self) -> AuditFinding:
        """Verifica se os servidores DNS em uso sao conhecidos e seguros.

        Servidores DNS desconhecidos podem redirecionar navegacao para sites falsos
        (DNS hijacking). Compara com lista de provedores seguros conhecidos.
        Nao requer elevacao para a leitura; a correcao (set DNS) exige admin.
        """
        problem_name = "Seguranca do DNS (protecao contra sites falsos)"
        SECURE_DNS = {
            "1.1.1.1", "1.0.0.1",           # Cloudflare
            "8.8.8.8", "8.8.4.4",           # Google
            "9.9.9.9", "149.112.112.112",    # Quad9
            "208.67.222.222", "208.67.220.220",  # OpenDNS
            "185.228.168.9", "185.228.169.9",    # CleanBrowsing
        }
        PRIVATE_PREFIXES = (
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "127.", "::1", "fd", "fe80",
        )

        def _is_trusted(ip: str) -> bool:
            if ip in SECURE_DNS:
                return True
            return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

        try:
            raw = self._run_powershell(
                "Get-DnsClientServerAddress -AddressFamily IPv4 "
                "| Where-Object { $_.ServerAddresses } "
                "| Select-Object -ExpandProperty ServerAddresses "
                "| Sort-Object -Unique",
                timeout=15,
            )
            dns_servers = [line.strip() for line in raw.strip().splitlines() if line.strip()]
            if not dns_servers:
                return _unknown(AuditCategory.NETWORK, problem_name, ValueError("Sem servidores DNS detectados"))

            untrusted = [ip for ip in dns_servers if not _is_trusted(ip)]
            trusted = [ip for ip in dns_servers if _is_trusted(ip)]

            if untrusted:
                return AuditFinding(
                    category=AuditCategory.NETWORK,
                    problem_name=problem_name,
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.VULNERABLE,
                    score=25,
                    evidence=[
                        f"DNS nao reconhecido em uso: {', '.join(untrusted)}",
                        "Servidores DNS desconhecidos podem redirecionar para sites falsos (DNS hijacking)",
                    ],
                    recommendation=(
                        "Substitua o DNS pelo Cloudflare (1.1.1.1) ou Google (8.8.8.8) "
                        "em: Configuracoes > Rede > Propriedades do adaptador > IPv4."
                    ),
                    resolver_key="dns_secure_set",
                    auto_resolvable=True,
                )

            return AuditFinding(
                category=AuditCategory.NETWORK,
                problem_name=problem_name,
                severity=AuditSeverity.INFORMATIVE,
                status=AuditStatus.SAFE,
                score=0,
                evidence=[f"DNS em uso: {', '.join(trusted)} (provedor seguro reconhecido)"],
            )
        except Exception as exc:
            return _unknown(AuditCategory.NETWORK, problem_name, exc)

    # ------------------------------------------------------------------
    # Calculo de score e exportacao
    # ------------------------------------------------------------------

    def _calculate_score(self, findings: list[AuditFinding]) -> tuple[int, AuditStatus]:
        """Calcula o score total e o status geral com base nos achados."""
        total = sum(f.score for f in findings)
        if total >= AUDIT_SCORE_THRESHOLD_CRITICAL:
            return total, AuditStatus.CRITICAL
        if total >= AUDIT_SCORE_THRESHOLD_VULNERABLE:
            return total, AuditStatus.VULNERABLE
        if total >= AUDIT_SCORE_THRESHOLD_ATTENTION:
            return total, AuditStatus.ATTENTION
        return total, AuditStatus.SAFE

    def export_to_txt(self, report: AuditReport, filepath: Path) -> None:
        """Exporta o relatorio de auditoria para um arquivo TXT formatado."""
        lines: list[str] = [
            "=" * 66,
            "AUDITORIA AVANCADA DE SEGURANCA - SentinelaPC",
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            f"Score total: {report.total_score}  |  Status geral: {report.overall_status.value}",
            f"Total de achados: {len(report.findings)}",
            "=" * 66,
            "",
        ]
        # Agrupar por status para facilitar leitura
        for status in (
            AuditStatus.CRITICAL,
            AuditStatus.VULNERABLE,
            AuditStatus.ATTENTION,
            AuditStatus.UNKNOWN,
            AuditStatus.SAFE,
        ):
            group = [f for f in report.findings if f.status == status]
            if not group:
                continue
            lines.append(f"--- {status.value.upper()} ({len(group)}) ---")
            for f in group:
                lines.append(f"[{f.category.value}] {f.problem_name}")
                lines.append(f"  Severidade : {f.severity.value}  |  Score: {f.score}")
                if f.evidence:
                    lines.append("  Evidencias:")
                    for ev in f.evidence:
                        lines.append(f"    - {ev}")
                if f.recommendation:
                    lines.append(f"  Recomendacao: {f.recommendation}")
                if f.details:
                    lines.append(f"  Detalhes: {f.details}")
                lines.append("")
        filepath.write_text("\n".join(lines), encoding="utf-8")

    def export_to_json(self, report: AuditReport, filepath: Path) -> None:
        """Exporta o relatorio de auditoria para um arquivo JSON estruturado."""
        data: dict[str, Any] = {
            "generated_at": datetime.now().isoformat(),
            "total_score": report.total_score,
            "overall_status": report.overall_status.value,
            "interrupted": report.interrupted,
            "score_scale": {
                "Seguro": "0-19",
                "Atencao": "20-39",
                "Vulneravel": "40-69",
                "Critico": "70+",
            },
            "findings": [dataclasses.asdict(f) for f in report.findings],
        }
        filepath.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Utilitarios internos
    # ------------------------------------------------------------------

    def _run_powershell(self, command: str, timeout: int = 10) -> str:
        """Executa um comando PowerShell e retorna o stdout como string.

        Usa -NoProfile e -NonInteractive para reduzir o tempo de inicializacao.
        Levanta RuntimeError se o codigo de retorno nao for 0.
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"PowerShell retornou {result.returncode}: {result.stderr.strip()}")
        return result.stdout

    def _is_running_as_admin(self) -> bool:
        """Indica se o processo atual possui privilegios administrativos no Windows."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _collect_browser_findings(
        self,
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> list[AuditFinding]:
        """Converte a analise de navegadores em achados da auditoria avancada."""
        if self._browser_service is None:
            return [
                AuditFinding(
                    category=AuditCategory.BROWSER,
                    problem_name="Analise de navegadores na auditoria",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details="Servico de navegadores nao foi conectado a auditoria.",
                )
            ]

        report = self._browser_service.analyze_browsers(progress_callback=progress_callback, scan_control=scan_control)
        findings: list[AuditFinding] = []
        if not report.results:
            findings.append(
                AuditFinding(
                    category=AuditCategory.BROWSER,
                    problem_name="Risco de navegador e anti-phishing",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Nenhum executavel, extensao ou sinal local de hijack suspeito foi encontrado."],
                )
            )
        for item in report.results:
            findings.append(self._browser_item_to_finding(item))
        for error in report.errors:
            findings.append(
                AuditFinding(
                    category=AuditCategory.BROWSER,
                    problem_name=f"Falha ao verificar navegador: {error.source}",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details=error.message,
                )
            )
        return findings

    def _collect_email_findings(
        self,
        progress_callback: Callable[[str], None] | None,
        scan_control: ScanControl | None,
    ) -> list[AuditFinding]:
        """Converte a analise de e-mails exportados em achados da auditoria avancada."""
        if self._email_service is None:
            return [
                AuditFinding(
                    category=AuditCategory.EMAIL,
                    problem_name="Analise de e-mails na auditoria",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details="Servico de e-mails nao foi conectado a auditoria.",
                )
            ]

        email_sources = self._discover_default_email_sources()
        if not email_sources:
            return [
                AuditFinding(
                    category=AuditCategory.EMAIL,
                    problem_name="E-mails exportados suspeitos",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details="Nenhum arquivo .eml, .msg ou .txt de e-mail foi encontrado em Desktop, Downloads ou Documentos.",
                    recommendation="Use o modulo E-mails para selecionar manualmente arquivos ou pastas exportadas.",
                )
            ]

        report = self._email_service.analyze_email_sources(email_sources, progress_callback=progress_callback, scan_control=scan_control)
        findings: list[AuditFinding] = []
        if not report.results:
            findings.append(
                AuditFinding(
                    category=AuditCategory.EMAIL,
                    problem_name="Sinais de phishing em e-mails exportados",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.SAFE,
                    score=0,
                    evidence=["Nenhum e-mail exportado com score de phishing relevante foi encontrado nas origens padrao."],
                )
            )
        for item in report.results:
            findings.append(self._email_item_to_finding(item))
        for error in report.errors:
            findings.append(
                AuditFinding(
                    category=AuditCategory.EMAIL,
                    problem_name=f"Falha ao verificar e-mail exportado: {error.source.name}",
                    severity=AuditSeverity.INFORMATIVE,
                    status=AuditStatus.UNKNOWN,
                    score=0,
                    details=error.message,
                )
            )
        return findings

    def _discover_default_email_sources(self) -> list[Path]:
        """Busca arquivos de e-mail exportados em pastas de usuario mais provaveis."""
        sources: list[Path] = []
        seen: set[Path] = set()
        candidate_roots = [Path.home() / "Desktop", Path.home() / "Downloads", Path.home() / "Documents"]
        for root in candidate_roots:
            if not root.exists():
                continue
            for pattern in ("*.eml", "*.msg", "*.txt"):
                for file_path in root.rglob(pattern):
                    if file_path in seen:
                        continue
                    seen.add(file_path)
                    sources.append(file_path)
                    if len(sources) >= 50:
                        return sources
        return sources

    def _browser_item_to_finding(self, item: BrowserScanItem) -> AuditFinding:
        severity, status = self._map_risk_to_audit(item.score, item.risk_level, item.classification)
        evidence = [f"Navegador: {item.browser}", f"Tipo: {item.item_type}"]
        if item.path is not None:
            evidence.append(f"Caminho: {item.path}")
        evidence.extend(item.reasons)
        recommendation = self._browser_recommendation(item)
        return AuditFinding(
            category=AuditCategory.BROWSER,
            problem_name=f"{item.browser}: {item.item_type} suspeito",
            severity=severity,
            status=status,
            score=item.score,
            evidence=evidence,
            recommendation=recommendation,
        )

    def _email_item_to_finding(self, item: EmailScanItem) -> AuditFinding:
        severity, status = self._map_risk_to_audit(item.score, item.risk_level, item.classification)
        evidence = [
            f"Origem: {item.source_label or item.source_file}",
            f"Remetente: {item.sender}",
            f"Assunto: {item.subject}",
            f"Links encontrados: {item.links_found}",
            f"Anexos encontrados: {item.attachments_found}",
        ]
        evidence.extend(item.reasons)
        return AuditFinding(
            category=AuditCategory.EMAIL,
            problem_name=(
                "E-mail online com sinais de phishing"
                if item.source_kind == "online"
                else "E-mail exportado com sinais de phishing"
            ),
            severity=severity,
            status=status,
            score=item.score,
            evidence=evidence,
            recommendation=(
                "Nao clique em links, nao abra anexos executaveis e valide o remetente por canal oficial. "
                "Use o modulo E-mails para revisar os itens manualmente."
            ),
        )

    def _map_risk_to_audit(
        self,
        score: int,
        risk_level: RiskLevel,
        classification: ThreatClassification,
    ) -> tuple[AuditSeverity, AuditStatus]:
        """Converte classificacoes de outros modulos para a linguagem da auditoria."""
        if classification == ThreatClassification.MALICIOUS or score >= 70:
            return AuditSeverity.CRITICAL, AuditStatus.CRITICAL
        if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} or score >= 40:
            return AuditSeverity.HIGH, AuditStatus.VULNERABLE
        if risk_level == RiskLevel.MEDIUM or score >= 20:
            return AuditSeverity.MEDIUM, AuditStatus.ATTENTION
        if score > 0:
            return AuditSeverity.LOW, AuditStatus.ATTENTION
        return AuditSeverity.INFORMATIVE, AuditStatus.SAFE

    def _browser_recommendation(self, item: BrowserScanItem) -> str:
        if item.item_type.lower() == "extensao":
            return "Revise a extensao no navegador e remova se nao reconhecer o publisher ou as permissoes solicitadas."
        if "hijack" in item.item_type.lower():
            return "Restaure homepage, busca padrao e atalhos do navegador. Verifique tambem proxy e notificacoes do site."
        if item.item_type.lower() == "executavel":
            return "Confirme a origem do executavel do navegador e reinstale o navegador a partir do site oficial se necessario."
        return "Revise o achado no modulo Navegadores para validacao detalhada."


# ------------------------------------------------------------------
# Funcoes auxiliares de modulo (nao publicas)
# ------------------------------------------------------------------

def _unknown(category: AuditCategory, problem_name: str, exc: Exception) -> AuditFinding:
    """Cria um achado UNKNOWN padronizado quando uma excecao impede a verificacao."""
    return AuditFinding(
        category=category,
        problem_name=problem_name,
        severity=AuditSeverity.INFORMATIVE,
        status=AuditStatus.UNKNOWN,
        score=0,
        details=f"Nao foi possivel verificar: {type(exc).__name__}: {exc}",
    )


def _not_windows(category: AuditCategory, problem_name: str) -> AuditFinding:
    """Retorna UNKNOWN para checagens que exigem Windows mas winreg nao esta disponivel."""
    return AuditFinding(
        category=category,
        problem_name=problem_name,
        severity=AuditSeverity.INFORMATIVE,
        status=AuditStatus.UNKNOWN,
        score=0,
        details="Verificacao disponivel apenas no Windows",
    )


def _parse_wmi_date(raw: str) -> datetime | None:
    """Tenta parsear uma data retornada pelo WMI/PowerShell em varios formatos.

    Retorna None se nenhum formato compativel for encontrado.
    """
    if not raw:
        return None
    # Formato /Date(timestamp_ms)/
    match = re.search(r"/Date\((\d+)\)/", raw)
    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1)) / 1000)
        except Exception:
            pass
    # Formatos de data comuns
    for fmt in (
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(raw[:len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
    return None
