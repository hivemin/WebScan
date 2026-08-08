"""
tests/test_sqli_scanner.py

Prueba de humo: levanta el servidor vulnerable en un thread, lanza el
scanner contra /product (vulnerable) y /product_safe (parametrizado),
y comprueba que detecta el primero y no marca falsos positivos en el
segundo.

Ejecutar:
    pip install flask requests pyyaml
    python -m tests.test_sqli_scanner
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.http_client import HttpClient
from modules.sqli_scanner import SqliScanner
from tests.vulnerable_test_server import app


def run_server():
    app.run(port=5000, debug=False, use_reloader=False)


def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)  # dar tiempo a que el server levante

    client = HttpClient(rate_limit_per_sec=20)  # rápido porque es local
    scanner = SqliScanner(
        client,
        enable_error_based=True,
        enable_boolean_blind=True,
        enable_time_blind=False,  # desactivado en el test de humo por velocidad
    )

    print("=== Escaneando endpoint VULNERABLE (/product) ===")
    findings = scanner.scan_url("http://127.0.0.1:5000/product?id=1", method="GET")
    for f in findings:
        print(f"[{f.severity.value.upper()}] {f.title} -> param='{f.parameter}' payload={f.payload!r}")
    assert len(findings) > 0, "FALLO: no se detectó la inyección esperada"
    print(f"OK: {len(findings)} hallazgo(s) detectado(s) como se esperaba.\n")

    print("=== Escaneando endpoint SEGURO (/product_safe) ===")
    findings_safe = scanner.scan_url("http://127.0.0.1:5000/product_safe?id=1", method="GET")
    for f in findings_safe:
        print(f"[{f.severity.value.upper()}] {f.title} -> param='{f.parameter}'")
    assert len(findings_safe) == 0, "FALLO: falso positivo en endpoint parametrizado"
    print("OK: sin falsos positivos, como se esperaba.")


if __name__ == "__main__":
    main()
