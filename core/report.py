import json
import html as html_lib
from datetime import datetime, timezone
from typing import List
from core.findings import Finding, Severity

# Orden de severidad para ordenar findings de más a menos grave.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_COLOR = {
    "critical": "#7a0d0d",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2874a6",
    "info": "#5d6d7e",
}


def _sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def generate_json_report(findings: List[Finding], target: str, output_path: str) -> str:
    sorted_findings = _sort_findings(findings)
    report = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(sorted_findings),
        "summary_by_severity": _summary_by_severity(sorted_findings),
        "findings": [f.to_dict() for f in sorted_findings],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    return output_path


def _summary_by_severity(findings: List[Finding]) -> dict:
    summary = {sev.value: 0 for sev in Severity}
    for f in findings:
        summary[f.severity.value] += 1
    return summary


def generate_html_report(findings: List[Finding], target: str, output_path: str) -> str:
    sorted_findings = _sort_findings(findings)
    summary = _summary_by_severity(sorted_findings)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    summary_html = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLOR[sev]}">{sev.upper()}: {count}</span>'
        for sev, count in summary.items()
        if count > 0
    )

    rows_html = ""
    for f in sorted_findings:
        rows_html += f"""
        <div class="finding" style="border-left: 5px solid {_SEVERITY_COLOR[f.severity.value]}">
            <h3>
                <span class="badge" style="background:{_SEVERITY_COLOR[f.severity.value]}">{f.severity.value.upper()}</span>
                {html_lib.escape(f.title)}
            </h3>
            <table>
                <tr><td><b>Módulo</b></td><td>{html_lib.escape(f.module)}</td></tr>
                <tr><td><b>URL</b></td><td><code>{html_lib.escape(f.url)}</code></td></tr>
                <tr><td><b>Parámetro</b></td><td>{html_lib.escape(str(f.parameter))}</td></tr>
                <tr><td><b>Método</b></td><td>{html_lib.escape(f.method)}</td></tr>
                <tr><td><b>Confianza</b></td><td>{f.confidence.value}</td></tr>
                <tr><td><b>Payload</b></td><td><code>{html_lib.escape(str(f.payload))}</code></td></tr>
                <tr><td><b>Evidencia</b></td><td><pre>{html_lib.escape(f.evidence)}</pre></td></tr>
                <tr><td><b>Descripción</b></td><td>{html_lib.escape(f.description)}</td></tr>
                <tr><td><b>Remediación</b></td><td>{html_lib.escape(f.remediation)}</td></tr>
            </table>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de auditoría - {html_lib.escape(target)}</title>
<style>
    body {{ font-family: -apple-system, Arial, sans-serif; background: #f4f6f7; margin: 0; padding: 2rem; color: #222; }}
    h1 {{ margin-bottom: 0.2rem; }}
    .meta {{ color: #666; margin-bottom: 1.5rem; }}
    .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-right: 6px; }}
    .finding {{ background: white; padding: 1rem 1.5rem; margin-bottom: 1rem; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    td {{ padding: 4px 8px; vertical-align: top; border-bottom: 1px solid #eee; }}
    pre {{ white-space: pre-wrap; word-break: break-all; background: #f9f9f9; padding: 6px; border-radius: 3px; }}
    code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }}
</style>
</head>
<body>
    <h1>Informe de auditoría de seguridad</h1>
    <div class="meta">
        Target: <code>{html_lib.escape(target)}</code><br>
        Generado: {generated_at}<br>
        Total de hallazgos: {len(sorted_findings)}
    </div>
    <div class="summary">{summary_html}</div>
    <hr>
    {rows_html if rows_html else "<p>No se encontraron hallazgos.</p>"}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
