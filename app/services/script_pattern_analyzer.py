"""Analise profunda de conteudo de scripts por tipo para detectar padroes de ataque."""

from __future__ import annotations

from pathlib import Path

from app.services.risk_engine import RiskSignal


class ScriptPatternAnalyzer:
    """Inspeciona o conteudo textual de scripts por tipo para detectar padroes perigosos.

    Diferente do StaticFileAnalyzer que verifica o cabecalho e entropia,
    este analisador reconhece padroes semanticos especificos de cada linguagem de script:
    BAT/CMD, PowerShell, VBScript, JavaScript/JSE e WSF/HTA.

    O numero de sinais por arquivo e limitado para evitar acumulo artificial de score
    em scripts longos que tenham varios matches de baixo peso.
    """

    SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta",
    })

    # Peso por padrao para BAT/CMD
    _BAT_CMD: dict[str, int] = {
        "powershell -":             26,
        "powershell.exe":           22,
        "certutil -decode":         32,
        "certutil.exe -":           28,
        "bitsadmin /transfer":      30,
        "net user /add":            32,
        "net localgroup administrators": 36,
        "schtasks /create":         28,
        "reg add":                  20,
        "regsvr32 /s":              26,
        "rundll32":                 20,
        "msiexec /q":               20,
        "wmic process call":        28,
        "> %temp%":                 22,
        "start /b":                 16,
        "%comspec%":                16,
        "del /f /q":                14,
        "curl -o":                  16,
        "curl.exe -o":              16,
    }

    # Peso por padrao para PowerShell
    _PS1: dict[str, int] = {
        "-encodedcommand":              36,
        "invoke-expression":            30,
        "[convert]::frombase64string":  30,
        "downloadstring":               32,
        "downloadfile":                 28,
        "set-mppreference":             38,
        "add-mppreference":             30,
        "sc.exe stop":                  22,
        "net stop":                     20,
        "new-object system.net.webclient": 30,
        "start-process":                16,
        "-windowstyle hidden":          28,
        "invoke-webrequest":            22,
        "new-scheduledtask":            26,
        "set-itemproperty":             20,
        "reflection.assembly":          24,
        "::load(":                      22,
        "memorystream":                 18,
    }

    # Peso por padrao para VBScript
    _VBS: dict[str, int] = {
        "wscript.shell":            30,
        "shell.exec":               30,
        "createobject":             18,
        "createobject.*shell":      28,
        ".run ":                    22,
        "strreverse":               22,
        "execute ":                 24,
        "executestatement":         26,
        "activexobject":            26,
        "chr(":                     14,
        "shell.application":        24,
    }

    # Peso por padrao para JavaScript/JSE/HTA
    _JS_JSE: dict[str, int] = {
        "activexobject":            32,
        "new activexobject":        34,
        "wscript.shell":            32,
        "shell.exec":               30,
        "eval(unescape":            34,
        "eval(":                    20,
        "unescape(":                16,
        "string.fromcharcode":      22,
        "powershell":               28,
        "settimeout(":              10,
        "document.write(unescape":  30,
    }

    # Peso por padrao para WSF
    _WSF: dict[str, int] = {
        "wscript.shell":   30,
        "activexobject":   30,
        "shell.exec":      28,
        ".run(":           22,
        "createobject":    20,
        "downloadstring":  30,
    }

    _PATTERNS_BY_EXT: dict[str, dict[str, int]] = {
        ".bat":  _BAT_CMD,
        ".cmd":  _BAT_CMD,
        ".ps1":  _PS1,
        ".vbs":  _VBS,
        ".js":   _JS_JSE,
        ".jse":  _JS_JSE,
        ".hta":  _JS_JSE,
        ".wsf":  _WSF,
    }

    # Maximo de sinais emitidos por arquivo para evitar score inflado artificialmente
    MAX_SIGNALS = 5
    MAX_READ_BYTES = 65_536

    def analyze(self, file_path: Path) -> list[RiskSignal]:
        """Retorna sinais ponderados do conteudo do script."""
        extension = file_path.suffix.lower()
        patterns = self._PATTERNS_BY_EXT.get(extension)
        if not patterns:
            return []

        try:
            raw = file_path.read_bytes()[: self.MAX_READ_BYTES]
            content = raw.decode("utf-8", errors="ignore").lower()
        except OSError:
            return []

        signals: list[RiskSignal] = []
        # Ordena por peso descendente para capturar os mais graves primeiro
        for pattern, weight in sorted(patterns.items(), key=lambda item: item[1], reverse=True):
            if len(signals) >= self.MAX_SIGNALS:
                break
            if pattern in content:
                signals.append(
                    RiskSignal(
                        reason=f"Script ({extension}) com padrao perigoso: '{pattern}'",
                        weight=weight,
                        category="script_malicioso",
                        module="script_pattern_analyzer",
                    )
                )

        return signals
