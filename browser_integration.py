"""Ponto de entrada da API local para integracao do SentinelaPC com Electron.

Protocolo stdin/stdout (JSON por linha):
Entrada:
{"id":"1","command":"ping","params":{}}
Saida:
{"id":"1","ok":true,"status":"running","message":"Antivirus conectado", ...}
"""

from __future__ import annotations

import json
import sys
from typing import Any

from app.integration.antivirus_bridge import AntivirusBridge, get_bridge


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def _build_bridge_from_args(argv: list[str]) -> AntivirusBridge:
    """Extrai argumentos globais de inicializacao e monta o bridge singleton."""
    installation_path: str | None = None

    args = argv[1:]
    for index, argument in enumerate(args):
        if argument == "--installation-path" and index + 1 < len(args):
            installation_path = args[index + 1]
            break

    return get_bridge(installation_path=installation_path)


def _extract_runtime_arguments(argv: list[str]) -> tuple[bool, list[str]]:
    """Separa flags globais dos argumentos do comando de execucao."""
    args = argv[1:]
    force_stdio = False
    remaining: list[str] = []

    index = 0
    while index < len(args):
        argument = args[index]

        if argument == "--stdio":
            force_stdio = True
            index += 1
            continue

        if argument == "--installation-path":
            index += 2
            continue

        remaining = args[index:]
        break

    return force_stdio, remaining


def _run_one_shot(bridge: AntivirusBridge, argv: list[str]) -> int:
    command = argv[1]
    params: dict[str, Any] = {}

    if len(argv) >= 3:
        try:
            raw_params = json.loads(argv[2])
            if isinstance(raw_params, dict):
                params = raw_params
        except json.JSONDecodeError:
            _print_json(
                {
                    "ok": False,
                    "status": "error",
                    "message": "Falha ao executar comando",
                    "error": "JSON de parametros invalido",
                }
            )
            return 2

    response = bridge.execute(command, params)
    _print_json(response)
    return 0 if response.get("ok") else 2


def _run_stdio_server(bridge: AntivirusBridge) -> int:
    _print_json(
        {
            "ok": True,
            "status": "running",
            "message": "Bridge de integracao inicializada",
            "data": {
                "protocol": "jsonl-stdin-stdout",
                "commands": [
                    "get_status",
                    "validate_file",
                    "scan_download",
                    "check_url",
                    "ping",
                    "get_version",
                ],
            },
        }
    )

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        request_id: Any = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Formato de requisicao invalido")

            request_id = request.get("id")
            command = request.get("command")
            params = request.get("params") if isinstance(request.get("params"), dict) else {}

            if command == "shutdown":
                _print_json(
                    {
                        "id": request_id,
                        "ok": True,
                        "status": "stopped",
                        "message": "Bridge encerrada",
                    }
                )
                return 0

            if not isinstance(command, str):
                response = {
                    "ok": False,
                    "status": "error",
                    "message": "Comando invalido",
                    "error": "Campo command ausente ou invalido",
                }
            else:
                response = bridge.execute(command, params)

        except Exception as error:
            response = {
                "ok": False,
                "status": "error",
                "message": "Falha ao processar requisicao",
                "error": str(error),
            }

        response_with_id = {"id": request_id, **response}
        _print_json(response_with_id)

    return 0


def main() -> int:
    argv = sys.argv
    bridge = _build_bridge_from_args(argv)
    force_stdio, remaining_args = _extract_runtime_arguments(argv)

    if remaining_args and not force_stdio:
        synthetic_argv = [argv[0], *remaining_args]
        return _run_one_shot(bridge, synthetic_argv)

    return _run_stdio_server(bridge)


if __name__ == "__main__":
    raise SystemExit(main())
