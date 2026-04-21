#!/usr/bin/env python3
"""
PHALANX Reporting Module – Generate PDF/HTML reports.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict

def generate_report(report_data: Dict, config: Dict, output_dir: Path) -> Path:
    """Generate an HTML report (and optionally PDF)."""
    html_template = config.get("reporting", {}).get("html_template", "default")
    # Simple HTML generation
    html = f"""
    <html>
    <head><title>PHALANX Pentest Report</title></head>
    <body>
    <h1>PHALANX Pentest Report</h1>
    <p>Target: {report_data['session']['target']}</p>
    <p>Date: {datetime.now().isoformat()}</p>
    <h2>Objectives</h2>
    <ul>
    """
    for obj in report_data.get("objectives", []):
        html += f"<li>{obj['description']} – {obj['status']}</li>"
    html += "</ul><h2>Vulnerabilities</h2><ul>"
    for vuln in report_data.get("vulnerabilities", []):
        html += f"<li>{vuln['name']} ({vuln['severity']}) – {vuln.get('cve', 'N/A')}</li>"
    html += "</ul><h2>Exploits</h2><ul>"
    for exp in report_data.get("exploits", []):
        html += f"<li>{exp['name']} – {'Success' if exp['success'] else 'Failed'}</li>"
    html += "</ul></body></html>"
    report_path = output_dir / f"report_{report_data['session']['session_id']}.html"
    report_path.write_text(html)
    # Optionally convert to PDF using weasyprint
    if config.get("reporting", {}).get("pdf_enabled", False):
        try:
            from weasyprint import HTML
            pdf_path = report_path.with_suffix(".pdf")
            HTML(string=html).write_pdf(pdf_path)
            return pdf_path
        except ImportError:
            pass
    return report_path
