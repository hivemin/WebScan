"""
tests/test_full_report.py

Corre los tres scanners contra el servidor de juguete y genera un
informe combinado (JSON + HTML) en reports/, para comprobar que
core/report.py funciona con datos reales de los tres módulos.
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.http_client import HttpClient
from core.report import generate_json_report, generate_html_report
from modules.sqli_scanner import SqliScanner
from modules.xss_scanner import XssScanner
from modules.auth_scanner import AuthScanner
from tests.vulnerable_test_server import app, JWT_SECRET
import jwt as pyjwt


def run_server():
    app.run(port=5000, debug=False, use_reloader=False)


def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)

    client = HttpClient(rate_limit_per_sec=20)
    all_findings = []

    sqli = SqliScanner(client, enable_time_blind=False)
    all_findings += sqli.scan_url("http://127.0.0.1:5000/product?id=1", method="GET")

    xss = XssScanner(client)
    all_findings += xss.scan_url("http://127.0.0.1:5000/search?q=hola", method="GET")

    auth = AuthScanner(client)
    f1 = auth.check_login_rate_limiting(
        "http://127.0.0.1:5000/login", "username", "password", "admin", num_attempts=6
    )
    if f1:
        all_findings.append(f1)

    valid_token = pyjwt.encode({"user": "admin"}, JWT_SECRET, algorithm="HS256")
    f2 = auth.check_jwt_alg_none("http://127.0.0.1:5000/admin/dashboard", valid_token)
    if f2:
        all_findings.append(f2)
    f3 = auth.check_jwt_weak_secret(valid_token)
    if f3:
        all_findings.append(f3)

    os.makedirs("reports", exist_ok=True)
    json_path = generate_json_report(all_findings, "http://127.0.0.1:5000 (demo)", "reports/demo_report.json")
    html_path = generate_html_report(all_findings, "http://127.0.0.1:5000 (demo)", "reports/demo_report.html")

    print(f"Total findings: {len(all_findings)}")
    print(f"JSON generado en: {json_path}")
    print(f"HTML generado en: {html_path}")
    assert len(all_findings) >= 5, "FALLO: se esperaban al menos 5 hallazgos combinados"
    print("OK: informe combinado generado correctamente.")


if __name__ == "__main__":
    main()
