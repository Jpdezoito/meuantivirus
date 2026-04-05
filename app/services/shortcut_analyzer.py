"""Analisa atalhos .lnk para detectar destinos de execucao perigosos antes do clique."""

from __future__ import annotations

from pathlib import Path

from app.services.risk_engine import RiskSignal


class ShortcutAnalyzer:
    """Inspeciona o binario de arquivos .lnk procurando destinos e argumentos suspeitos.

    A busca e feita tanto nos bytes crus (strings ASCII que o LNK armazena internamente)
    quanto no conteudo decodificado em UTF-16LE (formato padrao dos campos de texto do LNK).
    Essa dupla cobertura garante deteccao mesmo quando o alvo esta codificado em Unicode.
    """

    LNK_MAGIC = b"\x4c\x00\x00\x00"

    # Processo alvo suspeito no atalho (apenas o sinal de maior peso e emitido)
    _DANGEROUS_TARGETS: dict[bytes, int] = {
        b"mshta":        34,
        b"wscript":      30,
        b"cscript":      30,
        b"powershell":   28,
        b"pwsh":         26,
        b"certutil":     26,
        b"bitsadmin":    26,
        b"regsvr32":     24,
        b"rundll32":     22,
        b"installutil":  22,
        b"wmic":         20,
        b"cmd.exe":      18,
        b"msiexec":      16,
    }

    # Argumentos suspeitos no alvo do atalho (apenas o de maior peso e emitido)
    _DANGEROUS_ARGS: dict[bytes, int] = {
        b"-encodedcommand": 34,
        b"downloadstring":  32,
        b"frombase64string": 28,
        b"invoke-expression": 28,
        b" iex ":           26,
        b"-windowstyle hidden": 26,
        b"bypass":           24,
        b"invoke-webrequest": 22,
        b"-noprofile":       16,
        b"/c powershell":   30,
        b"start /b":        14,
    }

    def analyze(self, file_path: Path) -> list[RiskSignal]:
        """Retorna sinais de risco encontrados no atalho .lnk."""
        signals: list[RiskSignal] = []

        try:
            content = file_path.read_bytes()
        except OSError:
            return signals

        if not content.startswith(self.LNK_MAGIC):
            return signals  # Nao e um LNK valido (magic bytes incorretos)

        # Combina bytes brutos + decode UTF-16LE para cobertura maxima
        lowered_raw = content.lower()
        try:
            utf16_decoded = content.decode("utf-16-le", errors="ignore").lower().encode("utf-8", errors="ignore")
        except Exception:
            utf16_decoded = b""

        combined = lowered_raw + utf16_decoded

        # Emite o sinal de alvo mais pesado encontrado
        best_target = max(
            (tgt for tgt in self._DANGEROUS_TARGETS if tgt in combined),
            key=lambda t: self._DANGEROUS_TARGETS[t],
            default=None,
        )
        if best_target is not None:
            signals.append(
                RiskSignal(
                    reason=f"Atalho .lnk aponta para processo suspeito: {best_target.decode('ascii', errors='replace')}",
                    weight=self._DANGEROUS_TARGETS[best_target],
                    category="lnk_suspeito",
                    module="shortcut_analyzer",
                )
            )

        # Emite o sinal de argumento mais pesado encontrado
        best_arg = max(
            (arg for arg in self._DANGEROUS_ARGS if arg in combined),
            key=lambda a: self._DANGEROUS_ARGS[a],
            default=None,
        )
        if best_arg is not None:
            signals.append(
                RiskSignal(
                    reason=f"Argumento perigoso em atalho .lnk: {best_arg.decode('ascii', errors='replace').strip()}",
                    weight=self._DANGEROUS_ARGS[best_arg],
                    category="lnk_payload",
                    module="shortcut_analyzer",
                )
            )

        return signals
