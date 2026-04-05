"""Motor heuristico simples usado pelos modulos de diagnostico do SentinelaPC."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re
import subprocess
import sys

from app.core.risk import RiskLevel, ThreatClassification


@dataclass(frozen=True)
class HeuristicEvaluation:
    """Representa o resultado de uma avaliacao heuristica individual."""

    score: int
    risk_level: RiskLevel
    classification: ThreatClassification
    reasons: list[str] = field(default_factory=list)
    explanation: str = ""


class HeuristicEngine:
    """Centraliza regras simples de pontuacao para diferentes tipos de sinal."""

    TRUSTED_MAX_SCORE = 19
    SUSPICIOUS_MAX_SCORE = 69  # Aumentado de 59 para reduzir falsos positivos

    TRUSTED_PATH_MARKERS = (
        "\\windows\\system32\\",
        "\\program files\\",
        "\\program files (x86)\\",
    )

    TEMP_PATH_MARKERS = (
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\tmp\\",
    )

    UNUSUAL_PATH_MARKERS = (
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\appdata\\roaming\\",
        "\\programdata\\",
        "\\recycler\\",
        "\\$recycle.bin\\",
    )

    WELL_KNOWN_PROCESS_NAMES = {
        "svchost.exe",
        "explorer.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "dwm.exe",
    }

    TRUSTED_NAME_PATH_HINTS: dict[str, tuple[str, ...]] = {
        # ─── Windows System ────────────────────────────────────────
        "explorer.exe": ("\\windows\\",),
        "searchindexer.exe": ("\\windows\\system32\\",),
        "svchost.exe": ("\\windows\\system32\\",),
        "dwm.exe": ("\\windows\\system32\\",),
        "taskhostw.exe": ("\\windows\\system32\\",),
        "conhost.exe": ("\\windows\\system32\\",),
        "cmd.exe": ("\\windows\\system32\\",),
        "powershell.exe": ("\\windows\\system32\\",),
        "rundll32.exe": ("\\windows\\system32\\",),
        "regsvr32.exe": ("\\windows\\system32\\",),
        "svchost.exe": ("\\windows\\system32\\",),
        "csrss.exe": ("\\windows\\system32\\",),
        "lsass.exe": ("\\windows\\system32\\",),
        "services.exe": ("\\windows\\system32\\",),
        "winlogon.exe": ("\\windows\\system32\\",),
        "smss.exe": ("\\windows\\system32\\",),
        
        # ─── Microsoft Applications ────────────────────────────────
        "msedge.exe": ("\\program files", "\\microsoft\\edge"),
        "microsoft edge.lnk": ("\\microsoft\\edge",),
        "winword.exe": ("\\program files", "\\microsoft office"),
        "excel.exe": ("\\program files", "\\microsoft office"),
        "outlook.exe": ("\\program files", "\\microsoft office"),
        "powerpnt.exe": ("\\program files", "\\microsoft office"),
        "notepad.exe": ("\\windows\\",),
        "mspaint.exe": ("\\windows\\",),
        "calc.exe": ("\\windows\\",),
        "onenote.exe": ("\\program files", "\\microsoft office"),
        "skype.exe": ("\\program files", "\\skype"),
        "teams.exe": ("\\program files", "\\microsoft\\teams"),
        "onedrive.exe": ("\\program files", "\\microsoft onedrive"),
        "windowsupdateforservicestackhostfile.exe": ("\\windows\\",),
        
        # ─── Google/Chrome ────────────────────────────────────────
        "chrome.exe": ("\\program files", "\\google\\chrome"),
        "google chrome.lnk": ("\\google\\chrome",),
        "swiftshader_indirect.dll": ("\\google\\chrome",),
        
        # ─── Development Tools ────────────────────────────────────
        "python.exe": ("\\python", "program files"),
        "pythonw.exe": ("\\python", "program files"),
        "python314.exe": ("\\python", "program files"),
        "code.exe": ("\\microsoft vs code", "\\program files"),
        "git.exe": ("\\git\\", "\\program files"),
        "git-bash.exe": ("\\git\\", "program files"),
        "github desktop.exe": ("\\github desktop", "\\program files"),
        "idea.exe": ("\\jetbrains", "\\program files"),
        "goland.exe": ("\\jetbrains", "\\program files"),
        "webstorm.exe": ("\\jetbrains", "\\program files"),
        "studio.exe": ("\\android studio", "\\program files"),
        "java.exe": ("\\java", "program files"),
        "javaw.exe": ("\\java", "program files"),
        "javac.exe": ("\\java", "program files"),
        "node.exe": ("\\nodejs", "program files"),
        "npm.cmd": ("\\nodejs", "program files"),
        "npm.ps1": ("\\nodejs", "program files"),
        "pip.exe": ("\\python", "program files"),
        "pip3.exe": ("\\python", "program files"),
        
        # ─── Entertainment & Misc ──────────────────────────────────
        "steam.exe": ("\\program files", "\\steam\\"),
        "steamworksexternalruntime.exe": ("\\steam\\",),
        "discord.exe": ("\\discord", "\\program files"),
        "vlc.exe": ("\\videolan", "\\program files"),
        "7z.exe": ("\\7-zip", "\\program files"),
        "winrar.exe": ("\\winrar", "\\program files"),
        "unrar.exe": ("\\winrar", "program files"),
        "filmoraPro.exe": ("\\fimesoft", "\\program files"),
        "filmoratray.exe": ("\\wondershare", "\\program files"),
        "audacity.exe": ("\\audacity", "\\program files"),
        "ffmpeg.exe": ("\\ffmpeg", "program files"),
        
        # ─── Browser Extensions (Chromium) ─────────────────────────
        "extension.crx": ("\\chrome\\extensions\\",),
        "manifest.json": ("\\chrome\\extensions\\",),
    }

    TRUSTED_PUBLISHERS = (
        # ─── Tech Giants ──────────────────────────────────────────
        "microsoft",
        "google",
        "apple",
        "amazon",
        "meta",
        "github",
        "jetbrains",
        "vmware",
        "oracle",
        
        # ─── Development ─────────────────────────────────────────
        "python software foundation",
        "mozilla foundation",
        "ruby core",
        "node foundation",
        "golang",
        "rust foundation",
        
        # ─── Entertainment/Media ─────────────────────────────────
        "valve",
        "discord",
        "riot games",
        "epic games",
        "steam",
        
        # ─── Utilities ───────────────────────────────────────────
        "7-zip",
        "winrar",
        "adobe",
        "nvidia",
        "amd",
        "intel",
        "realtek",
        "logitech",
        "corsair",
        
        # ─── Other ──────────────────────────────────────────────
        "wondershare",
        "davinci resolve",
        "blender",
    )

    _LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

    def __init__(self, trusted_hashes_file: Path | None = None) -> None:
        self._signature_cache: dict[str, str | None] = {}
        self._trusted_hashes: set[str] = self._load_trusted_hashes(trusted_hashes_file)

    def _load_trusted_hashes(self, hashes_file: Path | None) -> set[str]:
        """Carrega SHA-256 de arquivos que foram verificados como confiáveis."""
        if hashes_file is None:
            hashes_file = Path(__file__).parent.parent / "data" / "trusted_hashes.json"
        
        if not hashes_file.exists():
            return set()
        
        try:
            with hashes_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "hashes" in data:
                    return set(h.lower() for h in data["hashes"] if isinstance(h, str))
                elif isinstance(data, list):
                    return set(h.lower() for h in data if isinstance(h, str))
        except (json.JSONDecodeError, OSError):
            pass
        
        return set()

    def evaluate_file(
        self,
        *,
        path: Path,
        extension: str,
        is_sensitive_extension: bool,
        is_temporary_location: bool,
        is_unusual_location: bool,
        signature_publisher: str | None = None,
    ) -> HeuristicEvaluation:
        """Calcula risco heuristico de um arquivo analisado."""
        score, reasons = self.calculate_file_risk_score(
            path=path,
            extension=extension,
            is_sensitive_extension=is_sensitive_extension,
            is_temporary_location=is_temporary_location,
            is_unusual_location=is_unusual_location,
            signature_publisher=signature_publisher,
        )
        return self._build_evaluation(score, reasons)

    def calculate_file_risk_score(
        self,
        *,
        path: Path,
        extension: str,
        is_sensitive_extension: bool,
        is_temporary_location: bool,
        is_unusual_location: bool,
        signature_publisher: str | None = None,
    ) -> tuple[int, list[str]]:
        """Calcula score de risco para arquivo com foco em reduzir falsos positivos."""
        score = 0
        reasons: list[str] = []

        normalized_extension = extension.lower()
        is_script = normalized_extension in {".ps1", ".vbs", ".bat", ".cmd", ".js"}
        is_executable = normalized_extension in {".exe", ".dll", ".jar", ".scr"}
        normalized_path = str(path).lower().replace("/", "\\")
        filename = path.name.lower()

        # Extensao sensivel isolada nao deve gerar alerta.
        if is_sensitive_extension and not is_script and not is_executable:
            reasons.append(f"Extensao observada: {normalized_extension}")

        if is_executable and is_temporary_location:
            score += 30
            reasons.append("Executavel em pasta temporaria")

        if is_script and is_temporary_location:
            score += 25
            reasons.append("Script em pasta temporaria")

        if is_script and is_unusual_location:
            score += 10
            reasons.append("Script em pasta comum de download/documento")

        if is_executable and is_unusual_location:
            score += 8
            reasons.append("Executavel em pasta comum de download/documento")

        if self._is_windows_name_impostor(filename):
            score += 40
            reasons.append("Nome imita processo conhecido do Windows")

        score, reasons = self._apply_trust_reductions(
            score,
            reasons,
            name=filename,
            normalized_path=normalized_path,
            signature_publisher=signature_publisher,
        )

        score += self._combined_signal_bonus(reasons)
        return max(0, score), reasons

    def evaluate_process(
        self,
        *,
        process_name: str,
        executable_path: Path | None,
        has_invalid_path: bool,
        is_temporary_location: bool,
        has_strange_name: bool,
        has_sustained_high_cpu: bool,
        has_sustained_high_memory: bool,
        signature_publisher: str | None = None,
    ) -> HeuristicEvaluation:
        """Calcula risco heuristico para um processo em execucao."""
        score, reasons = self.calculate_process_risk_score(
            process_name=process_name,
            executable_path=executable_path,
            has_invalid_path=has_invalid_path,
            is_temporary_location=is_temporary_location,
            has_strange_name=has_strange_name,
            has_sustained_high_cpu=has_sustained_high_cpu,
            has_sustained_high_memory=has_sustained_high_memory,
            signature_publisher=signature_publisher,
        )
        return self._build_evaluation(score, reasons)

    def calculate_process_risk_score(
        self,
        *,
        process_name: str,
        executable_path: Path | None,
        has_invalid_path: bool,
        is_temporary_location: bool,
        has_strange_name: bool,
        has_sustained_high_cpu: bool,
        has_sustained_high_memory: bool,
        signature_publisher: str | None = None,
    ) -> tuple[int, list[str]]:
        """Calcula score de risco para processos evitando sinalizar uso de recurso como prova principal."""
        score = 0
        reasons: list[str] = []

        normalized_name = process_name.lower()
        normalized_path = str(executable_path).lower().replace("/", "\\") if executable_path else ""

        if has_invalid_path:
            score += 20
            reasons.append("Processo sem caminho valido")

        if is_temporary_location:
            score += 30
            reasons.append("Executavel do processo esta em pasta temporaria")

        if has_strange_name:
            score += 15
            reasons.append(f"Nome do processo parece aleatorio: {process_name}")

        if self._is_windows_name_impostor(normalized_name):
            score += 40
            reasons.append("Nome imita processo conhecido do Windows")

        # CPU e memoria sao sinais complementares, nunca evidencia principal.
        if has_sustained_high_cpu:
            score += 5
            reasons.append("Consumo alto de CPU observado (sinal complementar)")

        if has_sustained_high_memory:
            score += 5
            reasons.append("Consumo alto de memoria observado (sinal complementar)")

        score, reasons = self._apply_trust_reductions(
            score,
            reasons,
            name=normalized_name,
            normalized_path=normalized_path,
            signature_publisher=signature_publisher,
        )

        score += self._combined_signal_bonus(reasons)
        return max(0, score), reasons

    def evaluate_startup(
        self,
        *,
        name: str,
        command: str,
        item_type: str,
        is_temporary_location: bool,
        uses_suspicious_interpreter: bool,
        is_run_once: bool,
        has_missing_path: bool,
        executable_path: Path | None = None,
        signature_publisher: str | None = None,
    ) -> HeuristicEvaluation:
        """Calcula risco heuristico para um item de inicializacao."""
        score, reasons = self.calculate_startup_risk_score(
            name=name,
            command=command,
            item_type=item_type,
            is_temporary_location=is_temporary_location,
            uses_suspicious_interpreter=uses_suspicious_interpreter,
            is_run_once=is_run_once,
            has_missing_path=has_missing_path,
            executable_path=executable_path,
            signature_publisher=signature_publisher,
        )
        return self._build_evaluation(score, reasons)

    def calculate_startup_risk_score(
        self,
        *,
        name: str,
        command: str,
        item_type: str,
        is_temporary_location: bool,
        uses_suspicious_interpreter: bool,
        is_run_once: bool,
        has_missing_path: bool,
        executable_path: Path | None = None,
        signature_publisher: str | None = None,
    ) -> tuple[int, list[str]]:
        """Calcula score de risco para persistencia de inicializacao."""
        score = 0
        reasons: list[str] = []

        normalized_name = name.lower()
        normalized_command = command.lower().replace("/", "\\")
        normalized_path = str(executable_path).lower().replace("/", "\\") if executable_path else ""

        if is_temporary_location:
            score += 35
            reasons.append("Item de inicializacao aponta para pasta temporaria")

        if uses_suspicious_interpreter:
            score += 15
            reasons.append("Comando usa interpretador frequentemente abusado")

        if is_run_once:
            score += 5
            reasons.append("Entrada de inicializacao do tipo RunOnce")

        if has_missing_path:
            score += 20
            reasons.append("Caminho referenciado nao existe")

        if item_type == "startup_folder" and normalized_name.endswith(".lnk") and not normalized_path:
            score += 5
            reasons.append("Atalho de startup sem alvo executavel resolvido")

        if self._is_windows_name_impostor(normalized_name):
            score += 40
            reasons.append("Nome imita processo conhecido do Windows")

        if "\\startup\\" in normalized_command and is_temporary_location:
            score += 30
            reasons.append("Persistencia de startup em local atipico")

        score, reasons = self._apply_trust_reductions(
            score,
            reasons,
            name=normalized_name,
            normalized_path=normalized_path,
            signature_publisher=signature_publisher,
        )

        score += self._combined_signal_bonus(reasons)
        return max(0, score), reasons

    def is_trusted_hash(self, sha256_hash: str) -> bool:
        """Verifica se um arquivo está na whitelist de hashes confiáveis."""
        return sha256_hash.lower() in self._trusted_hashes

    def apply_trusted_hash_reduction(self, score: int, reasons: list[str], sha256_hash: str) -> tuple[int, list[str]]:
        """Aplica redução massiva de score se o hash está confirmado como seguro."""
        if self.is_trusted_hash(sha256_hash):
            updated_reasons = list(reasons)
            updated_reasons.append("Hash confirmado em whitelist de arquivos confiáveis")
            return max(0, score - 80), updated_reasons
        return score, reasons

    def resolve_signature_publisher(self, file_path: Path | None) -> str | None:
        """Retorna o publisher da assinatura digital no Windows quando disponivel.

        A leitura e best effort e fica em cache para reduzir custo.
        """
        if file_path is None:
            return None

        path_text = str(file_path)
        if path_text in self._signature_cache:
            return self._signature_cache[path_text]

        if sys.platform != "win32" or not file_path.exists() or not file_path.is_file():
            self._signature_cache[path_text] = None
            return None

        command = (
            "$sig = Get-AuthenticodeSignature -FilePath \""
            + path_text.replace("\"", "\"\"")
            + "\"; "
            "if ($sig.SignerCertificate -and $sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject }"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            self._signature_cache[path_text] = None
            return None

        publisher = completed.stdout.strip() if completed.returncode == 0 else ""
        normalized = publisher.lower() if publisher else None
        self._signature_cache[path_text] = normalized
        return normalized

    def _combined_signal_bonus(self, reasons: list[str]) -> int:
        """Aumenta a pontuacao quando multiplos sinais aparecem juntos."""
        if len(reasons) >= 3:
            return 15
        if len(reasons) >= 2:
            return 10
        return 0

    def _build_evaluation(self, score: int, reasons: list[str]) -> HeuristicEvaluation:
        """Cria o objeto final da avaliacao heuristica."""
        classification = self.classify_threat(score)
        risk_level = self._classify_score(score)
        explanation = self.build_reason_summary(reasons)
        return HeuristicEvaluation(
            score=score,
            risk_level=risk_level,
            classification=classification,
            reasons=reasons,
            explanation=explanation,
        )

    def classify_threat(self, score: int) -> ThreatClassification:
        """Converte o score de risco em classificacao final de deteccao."""
        if score <= self.TRUSTED_MAX_SCORE:
            return ThreatClassification.TRUSTED
        if score <= self.SUSPICIOUS_MAX_SCORE:
            return ThreatClassification.SUSPICIOUS
        return ThreatClassification.MALICIOUS

    def build_custom_evaluation(self, score: int, reasons: list[str]) -> HeuristicEvaluation:
        """Permite que outros modulos reaproveitem a mesma logica de score/classificacao."""
        normalized_score = max(0, int(score))
        return self._build_evaluation(normalized_score, list(reasons))

    def build_reason_summary(self, reasons: list[str]) -> str:
        """Gera um resumo legivel dos motivos do score."""
        if not reasons:
            return "Sem sinais fortes de risco; item tratado como confiavel"
        return "; ".join(reasons)

    def _classify_score(self, score: int) -> RiskLevel:
        """Converte pontuacao em classificacao textual de risco."""
        if score >= 70:
            return RiskLevel.CRITICAL
        if score >= 40:
            return RiskLevel.HIGH
        if score >= 20:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _apply_trust_reductions(
        self,
        score: int,
        reasons: list[str],
        *,
        name: str,
        normalized_path: str,
        signature_publisher: str | None,
    ) -> tuple[int, list[str]]:
        """Aplica reducoes quando sinais de legitimidade estao presentes."""
        updated_score = score
        updated_reasons = list(reasons)

        if self._is_system32_path(normalized_path):
            updated_score -= 20
            updated_reasons.append("Caminho legitimo em Windows\\System32")
        elif self._is_program_files_path(normalized_path):
            updated_score -= 15
            updated_reasons.append("Caminho compativel com instalacao legitima em Program Files")

        if self._is_whitelisted_name_and_path(name, normalized_path):
            updated_score -= 35
            updated_reasons.append("Executavel conhecido em caminho compativel com whitelist")

        if self._has_trusted_publisher(signature_publisher):
            updated_score -= 20
            updated_reasons.append("Assinatura digital valida de editora confiavel")

        return max(0, updated_score), updated_reasons

    def _is_system32_path(self, normalized_path: str) -> bool:
        return "\\windows\\system32\\" in normalized_path

    def _is_program_files_path(self, normalized_path: str) -> bool:
        return "\\program files\\" in normalized_path or "\\program files (x86)\\" in normalized_path

    def _is_whitelisted_name_and_path(self, name: str, normalized_path: str) -> bool:
        normalized_name = name.lower()
        hints = self.TRUSTED_NAME_PATH_HINTS.get(normalized_name)
        if not hints:
            return False

        return all(hint in normalized_path for hint in hints)

    def _has_trusted_publisher(self, signature_publisher: str | None) -> bool:
        if not signature_publisher:
            return False

        publisher = signature_publisher.lower()
        return any(known in publisher for known in self.TRUSTED_PUBLISHERS)

    def _is_windows_name_impostor(self, process_name: str) -> bool:
        """Detecta nomes que imitam processos do Windows com pequenas alteracoes."""
        normalized = Path(process_name).name.lower()
        normalized = re.sub(r"[^a-z0-9._-]", "", normalized)
        translated = normalized.translate(self._LEET_TRANSLATION)

        for known in self.WELL_KNOWN_PROCESS_NAMES:
            if normalized == known:
                return False
            if translated == known and normalized != known:
                return True
            if self._levenshtein_distance(translated, known) == 1:
                return True
        return False

    def _levenshtein_distance(self, source: str, target: str) -> int:
        """Calcula distancia de Levenshtein em versao curta para comparacoes pequenas."""
        if source == target:
            return 0
        if not source:
            return len(target)
        if not target:
            return len(source)

        previous = list(range(len(target) + 1))
        for i, source_char in enumerate(source, start=1):
            current = [i]
            for j, target_char in enumerate(target, start=1):
                insert_cost = current[j - 1] + 1
                delete_cost = previous[j] + 1
                replace_cost = previous[j - 1] + (source_char != target_char)
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        return previous[-1]