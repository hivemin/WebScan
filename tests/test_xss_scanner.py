"""
tests/test_xss_scanner.py

Igual que el test de SQLi: levanta el servidor de juguete y compara
el comportamiento del scanner contra /search (vulnerable, sin
escapar) y /search_safe (con escape()).
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.http_client import HttpClient
from modules.xss_scanner import XssScanner
from tests.vulnerable_test_server import app


def run_server():
    app.run(port=5000, debug=False, use_reloader=False)


def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)

    client = HttpClient(rate_limit_per_sec=20)
    scanner = XssScanner(client)

    print("=== Escaneando endpoint VULNERABLE (/search) ===")
    findings = scanner.scan_url("http://127.0.0.1:5000/search?q=hola", method="GET")
    high_conf = [f for f in findings if f.severity.value in ("high", "critical")]
    for f in findings:
        print(f"[{f.severity.value.upper()}] {f.title} -> contexto en payload={f.payload!r}")
    assert len(high_conf) > 0, "FALLO: no se detectó XSS reflejado esperado"
    print(f"OK: {len(high_conf)} hallazgo(s) de severidad alta/crítica, como se esperaba.\n")

    print("=== Escaneando endpoint SEGURO (/search_safe) ===")
    findings_safe = scanner.scan_url("http://127.0.0.1:5000/search_safe?q=hola", method="GET")
    high_conf_safe = [f for f in findings_safe if f.severity.value in ("high", "critical")]
    for f in findings_safe:
        print(f"[{f.severity.value.upper()}] {f.title}")
    assert len(high_conf_safe) == 0, "FALLO: falso positivo en endpoint con escape()"
    print("OK: sin falsos positivos de severidad alta, como se esperaba.")
    print(
        f"(Nota: {len(findings_safe)} hallazgo(s) INFO de 'reflejado pero "
        f"saneado' son esperables y no son un fallo.)"
    )


if __name__ == "__main__":
    main()
