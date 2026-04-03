"""Servico de geracao de relatorios TXT e HTML da sessao atual."""

from __future__ import annotations

from html import escape
from pathlib import Path
import logging

from app.services.report_models import GeneratedReportFiles, SessionReportData


class ReportService:
    """Concentra a criacao, formatacao e gravacao dos relatorios do sistema."""

    def __init__(self, reports_dir: Path, logger: logging.Logger) -> None:
        self.reports_dir = reports_dir
        self.logger = logger

    def generate_session_report(self, session_data: SessionReportData) -> GeneratedReportFiles:
        """Gera arquivos TXT e HTML com base nos resultados reunidos na sessao."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = session_data.generated_at.strftime("%Y%m%d-%H%M%S")
        txt_file = self.reports_dir / f"sentinelapc-relatorio-{timestamp}.txt"
        html_file = self.reports_dir / f"sentinelapc-relatorio-{timestamp}.html"

        txt_file.write_text(self._build_txt_content(session_data), encoding="utf-8")
        html_file.write_text(self._build_html_content(session_data), encoding="utf-8")

        self.logger.info(
            "Relatorios gerados com sucesso | txt=%s | html=%s",
            txt_file,
            html_file,
        )
        return GeneratedReportFiles(txt_file=txt_file, html_file=html_file)

    def _build_txt_content(self, session_data: SessionReportData) -> str:
        """Monta uma versao textual limpa e objetiva do relatorio da sessao."""
        lines = [
            "SentinelaPC - Relatorio da sessao",
            "=" * 72,
            f"Data e hora da analise: {session_data.generated_at.strftime('%d/%m/%Y %H:%M:%S')}",
            f"Tipos de analise executados: {self._format_scan_types(session_data.executed_scan_types)}",
            f"Total de itens analisados: {self.count_total_analyzed(session_data)}",
            f"Total de itens suspeitos: {self.count_total_suspicious(session_data)}",
            "",
            "Achados detalhados",
            "-" * 72,
        ]

        lines.extend(self._build_txt_sections(session_data))
        lines.append("")
        lines.append("Acoes sugeridas")
        lines.append("-" * 72)
        lines.extend(self._build_suggested_actions(session_data))
        lines.append("")
        lines.append("Itens enviados para quarentena")
        lines.append("-" * 72)
        lines.extend(self._build_quarantine_lines(session_data))
        lines.append("")
        return "\n".join(lines)

    def _build_html_content(self, session_data: SessionReportData) -> str:
        """Monta uma pagina HTML simples, limpa e legivel para consulta visual."""
        sections_html = "".join(self._build_html_sections(session_data))
        actions_html = "".join(
            f"<li>{escape(action)}</li>" for action in self._build_suggested_actions(session_data)
        )
        quarantine_html = "".join(self._build_html_quarantine_items(session_data))

        return f"""<!DOCTYPE html>
<html lang=\"pt-BR\">
<head>
    <meta charset=\"utf-8\">
    <title>Relatorio SentinelaPC</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f3f5f7;
            color: #1f2933;
            margin: 0;
            padding: 32px;
        }}
        .page {{
            max-width: 1100px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 18px;
            padding: 32px;
            box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
        }}
        h1, h2 {{
            margin: 0 0 12px;
            color: #0f4c81;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 14px;
            margin: 24px 0;
        }}
        .card {{
            background: #f8fafc;
            border: 1px solid #d7e2ec;
            border-radius: 14px;
            padding: 16px;
        }}
        .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #52606d;
        }}
        .value {{
            font-size: 22px;
            font-weight: 700;
            margin-top: 6px;
        }}
        .section {{
            margin-top: 28px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }}
        th {{
            background: #f8fafc;
            color: #334e68;
        }}
        ul {{
            padding-left: 20px;
        }}
        .muted {{
            color: #61758a;
        }}
    </style>
</head>
<body>
    <div class=\"page\">
        <h1>SentinelaPC - Relatorio da sessao</h1>
        <p class=\"muted\">Gerado em {escape(session_data.generated_at.strftime('%d/%m/%Y %H:%M:%S'))}</p>

        <div class=\"summary\">
            <div class=\"card\"><div class=\"label\">Tipos de analise</div><div class=\"value\">{escape(self._format_scan_types(session_data.executed_scan_types))}</div></div>
            <div class=\"card\"><div class=\"label\">Itens analisados</div><div class=\"value\">{self.count_total_analyzed(session_data)}</div></div>
            <div class=\"card\"><div class=\"label\">Itens suspeitos</div><div class=\"value\">{self.count_total_suspicious(session_data)}</div></div>
            <div class=\"card\"><div class=\"label\">Quarentena na sessao</div><div class=\"value\">{len(session_data.quarantined_items)}</div></div>
        </div>

        <div class=\"section\">
            <h2>Achados detalhados</h2>
            {sections_html}
        </div>

        <div class=\"section\">
            <h2>Acoes sugeridas</h2>
            <ul>{actions_html}</ul>
        </div>

        <div class=\"section\">
            <h2>Itens enviados para quarentena</h2>
            {quarantine_html}
        </div>
    </div>
</body>
</html>
"""

    def _build_txt_sections(self, session_data: SessionReportData) -> list[str]:
        """Gera os blocos textuais para cada tipo de verificacao executada."""
        lines: list[str] = []
        lines.extend(self._build_file_section_txt(session_data))
        lines.extend(self._build_process_section_txt(session_data))
        lines.extend(self._build_startup_section_txt(session_data))
        lines.extend(self._build_diagnostics_section_txt(session_data))
        if not lines:
            lines.append("Nenhum scan foi executado na sessao atual.")
        return lines

    def _build_html_sections(self, session_data: SessionReportData) -> list[str]:
        """Gera os blocos HTML para cada secao de resultado disponivel."""
        sections: list[str] = []
        sections.extend(self._build_file_section_html(session_data))
        sections.extend(self._build_process_section_html(session_data))
        sections.extend(self._build_startup_section_html(session_data))
        sections.extend(self._build_diagnostics_section_html(session_data))
        if not sections:
            sections.append("<p class=\"muted\">Nenhum scan foi executado na sessao atual.</p>")
        return sections

    def _build_diagnostics_section_txt(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao textual do diagnostico de saude do sistema."""
        report = session_data.diagnostics_report
        if report is None:
            return []

        lines = [
            "[Diagnostico do sistema]",
            "Tipo de analise executada: diagnostico de saude do PC",
            "Total de itens analisados: 4 metricas principais + processos pesados + inicializacao + erros de acesso",
            f"Total de itens suspeitos: {len(report.issues)}",
            (
                f"- CPU: {report.cpu_usage_percent:.1f}% | Memoria: {report.memory_usage_percent:.1f}% | "
                f"Disco: {report.disk_usage_percent:.1f}% | Espaco livre: {report.free_disk_gb:.2f} GB"
            ),
            f"- Programas iniciando com o sistema: {report.startup_items_count}",
        ]

        if report.startup_programs:
            lines.append(f"- Exemplos de itens de startup: {', '.join(report.startup_programs)}")

        if report.heavy_processes:
            lines.append("- Processos mais pesados:")
            for process in report.heavy_processes:
                executable_path = process.executable_path or "caminho_indisponivel"
                lines.append(
                    (
                        f"  * {process.name} (PID {process.pid}) | CPU={process.cpu_usage_percent:.1f}% | "
                        f"MEM={process.memory_usage_percent:.1f}% | exe={executable_path}"
                    )
                )

        if report.slowdown_signals:
            lines.append("- Possiveis sinais de lentidao:")
            for signal in report.slowdown_signals:
                lines.append(f"  * {signal}")

        if report.path_errors:
            lines.append("- Erros simples de acesso ou caminhos invalidos detectados:")
            for error in report.path_errors:
                lines.append(f"  * {error.source} | {error.location} | {error.message}")

        if report.issues:
            lines.append("- Achados estruturados:")
            for issue in report.issues:
                lines.append(f"  * {issue.category} | severidade={issue.severity} | {issue.message}")

        lines.append("")
        return lines

    def _build_diagnostics_section_html(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao HTML do diagnostico de saude do sistema."""
        report = session_data.diagnostics_report
        if report is None:
            return []

        heavy_process_rows = "".join(
            (
                "<tr>"
                f"<td>{escape(process.name)}</td>"
                f"<td>{process.pid}</td>"
                f"<td>{process.cpu_usage_percent:.1f}%</td>"
                f"<td>{process.memory_usage_percent:.1f}%</td>"
                f"<td>{escape(str(process.executable_path) if process.executable_path else 'caminho_indisponivel')}</td>"
                "</tr>"
            )
            for process in report.heavy_processes
        ) or "<tr><td colspan=\"5\" class=\"muted\">Nenhum processo pesado relevante detectado.</td></tr>"

        issues_html = "".join(
            f"<li>{escape(issue.category)} | severidade={escape(issue.severity)} | {escape(issue.message)}</li>"
            for issue in report.issues
        )
        path_errors_html = "".join(
            f"<li>{escape(error.source)} | {escape(error.location)} | {escape(error.message)}</li>"
            for error in report.path_errors
        ) or "<li class=\"muted\">Nenhum erro simples de acesso detectado.</li>"
        slowdown_html = "".join(
            f"<li>{escape(signal)}</li>"
            for signal in report.slowdown_signals
        )

        return [
            (
                "<section class=\"section\">"
                "<h3>Diagnostico do sistema</h3>"
                f"<p class=\"muted\">Analise de saude do PC<br>CPU: {report.cpu_usage_percent:.1f}% | Memoria: {report.memory_usage_percent:.1f}% | "
                f"Disco: {report.disk_usage_percent:.1f}% | Livre: {report.free_disk_gb:.2f} GB | Startup: {report.startup_items_count}</p>"
                "<h4>Processos mais pesados</h4>"
                "<table><thead><tr><th>Processo</th><th>PID</th><th>CPU</th><th>Memoria</th><th>Executavel</th></tr></thead>"
                f"<tbody>{heavy_process_rows}</tbody></table>"
                "<h4>Sinais de lentidao</h4>"
                f"<ul>{slowdown_html}</ul>"
                "<h4>Achados</h4>"
                f"<ul>{issues_html}</ul>"
                "<h4>Erros de acesso ou caminhos invalidos</h4>"
                f"<ul>{path_errors_html}</ul>"
                "</section>"
            )
        ]

    def _build_file_section_txt(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao textual referente a verificacao de arquivos."""
        report = session_data.file_report
        if report is None:
            return []

        lines = [
            "[Arquivos]",
            f"Tipo de analise executada: {report.scan_label.lower()} em {report.target_directory}",
            f"Total de itens analisados: {report.scanned_files}",
            f"Total de itens suspeitos: {report.flagged_files}",
        ]
        if report.results:
            for result in report.results:
                lines.append(
                    (
                        f"- Arquivo: {result.path} | score={result.heuristic_score} | "
                        f"classe={result.final_classification.value} | risco={result.initial_risk_level.value} | motivo={result.alert_reason}"
                    )
                )
        else:
            lines.append("- Nenhum arquivo suspeito encontrado.")
        lines.append("")
        return lines

    def _build_process_section_txt(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao textual referente a verificacao de processos."""
        report = session_data.process_report
        if report is None:
            return []

        lines = [
            "[Processos]",
            "Tipo de analise executada: verificacao de processos ativos",
            f"Total de itens analisados: {report.inspected_processes}",
            f"Total de itens suspeitos: {report.suspicious_processes}",
        ]
        if report.results:
            for result in report.results:
                executable_path = result.executable_path or "caminho_indisponivel"
                lines.append(
                    (
                        f"- Processo: {result.name} (PID {result.pid}) | exe={executable_path} | "
                        f"score={result.heuristic_score} | classe={result.final_classification.value} | "
                        f"risco={result.initial_risk_level.value} | motivo={result.alert_reason}"
                    )
                )
        else:
            lines.append("- Nenhum processo suspeito encontrado.")
        lines.append("")
        return lines

    def _build_startup_section_txt(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao textual referente a inicializacao do Windows."""
        report = session_data.startup_report
        if report is None:
            return []

        lines = [
            "[Inicializacao]",
            "Tipo de analise executada: verificacao de itens de inicializacao do Windows",
            f"Total de itens analisados: {report.inspected_items}",
            f"Total de itens suspeitos: {report.suspicious_items}",
        ]
        if report.results:
            for result in report.results:
                lines.append(
                    (
                        f"- Item: {result.name} | origem={result.origin} | score={result.heuristic_score} | "
                        f"classe={result.final_classification.value} | risco={result.risk_level.value} | motivo={result.flag_reason}"
                    )
                )
        else:
            lines.append("- Nenhum item suspeito de inicializacao encontrado.")
        lines.append("")
        return lines

    def _build_file_section_html(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao HTML de verificacao de arquivos."""
        report = session_data.file_report
        if report is None:
            return []

        rows = "".join(
            (
                "<tr>"
                f"<td>{escape(str(result.path))}</td>"
                f"<td>{result.heuristic_score}</td>"
                f"<td>{escape(result.final_classification.value)}</td>"
                f"<td>{escape(result.initial_risk_level.value)}</td>"
                f"<td>{escape(result.alert_reason)}</td>"
                "</tr>"
            )
            for result in report.results
        )
        if not rows:
            rows = "<tr><td colspan=\"5\" class=\"muted\">Nenhum arquivo suspeito encontrado.</td></tr>"

        return [
            (
                "<section class=\"section\">"
                "<h3>Arquivos</h3>"
                f"<p class=\"muted\">Analise: {escape(report.scan_label.lower())} em {escape(str(report.target_directory))}<br>"
                f"Itens analisados: {report.scanned_files} | Suspeitos: {report.flagged_files}</p>"
                "<table><thead><tr><th>Arquivo</th><th>Score</th><th>Classe</th><th>Risco</th><th>Motivo</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
                "</section>"
            )
        ]

    def _build_process_section_html(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao HTML de verificacao de processos."""
        report = session_data.process_report
        if report is None:
            return []

        rows = "".join(
            (
                "<tr>"
                f"<td>{escape(result.name)}</td>"
                f"<td>{result.pid}</td>"
                f"<td>{result.heuristic_score}</td>"
                f"<td>{escape(result.final_classification.value)}</td>"
                f"<td>{escape(result.initial_risk_level.value)}</td>"
                f"<td>{escape(result.alert_reason)}</td>"
                "</tr>"
            )
            for result in report.results
        )
        if not rows:
            rows = "<tr><td colspan=\"6\" class=\"muted\">Nenhum processo suspeito encontrado.</td></tr>"

        return [
            (
                "<section class=\"section\">"
                "<h3>Processos</h3>"
                f"<p class=\"muted\">Analise: processos ativos<br>Itens analisados: {report.inspected_processes} | Suspeitos: {report.suspicious_processes}</p>"
                "<table><thead><tr><th>Processo</th><th>PID</th><th>Score</th><th>Classe</th><th>Risco</th><th>Motivo</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
                "</section>"
            )
        ]

    def _build_startup_section_html(self, session_data: SessionReportData) -> list[str]:
        """Monta a secao HTML de verificacao de inicializacao."""
        report = session_data.startup_report
        if report is None:
            return []

        rows = "".join(
            (
                "<tr>"
                f"<td>{escape(result.name)}</td>"
                f"<td>{escape(result.origin)}</td>"
                f"<td>{result.heuristic_score}</td>"
                f"<td>{escape(result.final_classification.value)}</td>"
                f"<td>{escape(result.risk_level.value)}</td>"
                f"<td>{escape(result.flag_reason)}</td>"
                "</tr>"
            )
            for result in report.results
        )
        if not rows:
            rows = "<tr><td colspan=\"6\" class=\"muted\">Nenhum item suspeito de inicializacao encontrado.</td></tr>"

        return [
            (
                "<section class=\"section\">"
                "<h3>Inicializacao</h3>"
                f"<p class=\"muted\">Analise: fontes de inicializacao do Windows<br>Itens analisados: {report.inspected_items} | Suspeitos: {report.suspicious_items}</p>"
                "<table><thead><tr><th>Item</th><th>Origem</th><th>Score</th><th>Classe</th><th>Risco</th><th>Motivo</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
                "</section>"
            )
        ]

    def _build_suggested_actions(self, session_data: SessionReportData) -> list[str]:
        """Cria uma lista simples de recomendacoes baseada nos achados da sessao."""
        actions: list[str] = []

        if session_data.file_report and session_data.file_report.flagged_files > 0:
            actions.append("Revisar arquivos suspeitos, validar hashes e manter em quarentena os itens nao confiaveis.")
        if session_data.process_report and session_data.process_report.suspicious_processes > 0:
            actions.append("Investigar processos suspeitos, confirmar o caminho do executavel e validar se pertencem a softwares conhecidos.")
        if session_data.startup_report and session_data.startup_report.suspicious_items > 0:
            actions.append("Auditar entradas de inicializacao suspeitas e remover ou desabilitar apenas itens confirmadamente indevidos.")
        if session_data.diagnostics_report and session_data.diagnostics_report.issues:
            actions.append("Usar o diagnostico do sistema para priorizar limpeza de inicializacao, revisao de processos pesados e liberacao de espaco em disco.")
        if session_data.quarantined_items:
            actions.append("Nao restaurar itens em quarentena sem confirmar a legitimidade do arquivo e do motivo original do alerta.")
        if not actions:
            actions.append("Nenhuma acao imediata sugerida. Os scans da sessao nao apontaram itens suspeitos relevantes.")

        actions.append("Manter logs e relatorios arquivados para comparacao com futuras verificacoes do sistema.")
        return actions

    def _build_quarantine_lines(self, session_data: SessionReportData) -> list[str]:
        """Gera a secao textual dos itens enviados para quarentena na sessao."""
        if not session_data.quarantined_items:
            return ["Nenhum item foi enviado para a quarentena nesta sessao."]

        return [
            (
                f"- {item.original_name} | origem={item.original_path} | destino={item.quarantined_path} | "
                f"risco={item.risk_level.value} | motivo={item.reason} | status={item.status}"
            )
            for item in session_data.quarantined_items
        ]

    def _build_html_quarantine_items(self, session_data: SessionReportData) -> list[str]:
        """Gera a secao HTML de itens colocados em quarentena durante a sessao."""
        if not session_data.quarantined_items:
            return ["<p class=\"muted\">Nenhum item foi enviado para a quarentena nesta sessao.</p>"]

        rows = "".join(
            (
                "<tr>"
                f"<td>{escape(item.original_name)}</td>"
                f"<td>{escape(str(item.original_path))}</td>"
                f"<td>{escape(item.risk_level.value)}</td>"
                f"<td>{escape(item.reason)}</td>"
                f"<td>{escape(item.status)}</td>"
                "</tr>"
            )
            for item in session_data.quarantined_items
        )
        return [
            (
                "<table><thead><tr><th>Nome</th><th>Origem</th><th>Risco</th><th>Motivo</th><th>Status</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        ]

    def _format_scan_types(self, executed_scan_types: list[str]) -> str:
        """Apresenta de forma legivel os tipos de analise executados na sessao."""
        if not executed_scan_types:
            return "nenhuma analise executada"
        return ", ".join(executed_scan_types)

    def count_total_analyzed(self, session_data: SessionReportData) -> int:
        """Soma todos os itens analisados nos scans disponiveis da sessao."""
        total = 0
        if session_data.file_report is not None:
            total += session_data.file_report.scanned_files
        if session_data.process_report is not None:
            total += session_data.process_report.inspected_processes
        if session_data.startup_report is not None:
            total += session_data.startup_report.inspected_items
        if session_data.diagnostics_report is not None:
            total += 4 + len(session_data.diagnostics_report.heavy_processes) + session_data.diagnostics_report.startup_items_count
        return total

    def count_total_suspicious(self, session_data: SessionReportData) -> int:
        """Soma todos os itens sinalizados como suspeitos nos scans da sessao."""
        total = 0
        if session_data.file_report is not None:
            total += session_data.file_report.flagged_files
        if session_data.process_report is not None:
            total += session_data.process_report.suspicious_processes
        if session_data.startup_report is not None:
            total += session_data.startup_report.suspicious_items
        if session_data.diagnostics_report is not None:
            total += len(session_data.diagnostics_report.issues)
        return total
