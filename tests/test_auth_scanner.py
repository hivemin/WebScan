"""
tests/test_auth_scanner.py

Prueba cada check del AuthScanner contra el servidor de juguete.
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.http_client import HttpClient
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
    scanner = AuthScanner(client)

    print("=== Check 1: rate limiting en /login ===")
    finding = scanner.check_login_rate_limiting(
        "http://127.0.0.1:5000/login",
        username_field="username",
        password_field="password",
        username_value="admin",
        num_attempts=8,
    )
    assert finding is not None, "FALLO: se esperaba detectar ausencia de rate limiting"
    print(f"OK: [{finding.severity.value.upper()}] {finding.title}\n")

    print("=== Check 2: flags de cookie de sesión ===")
    # La cookie se emite en la respuesta del POST /login, así que
    # llamamos al check con method="POST" y las credenciales válidas.
    findings_cookie = scanner.check_session_cookie_flags(
        "http://127.0.0.1:5000/login",
        cookie_name_hint="session_id",
        method="POST",
        data={"username": "admin", "password": "correct-horse-battery-staple"},
    )
    assert len(findings_cookie) > 0, "FALLO: se esperaba detectar cookie sin HttpOnly/Secure"
    for f in findings_cookie:
        print(f"OK: [{f.severity.value.upper()}] {f.title}")
    print()

    print("=== Check 3: JWT alg=none ===")
    valid_token = pyjwt.encode({"user": "admin"}, JWT_SECRET, algorithm="HS256")
    finding_none = scanner.check_jwt_alg_none("http://127.0.0.1:5000/admin/dashboard", valid_token)
    assert finding_none is not None, "FALLO: se esperaba que aceptara alg=none"
    print(f"OK: [{finding_none.severity.value.upper()}] {finding_none.title}\n")

    print("=== Check 4: JWT secreto débil ===")
    finding_weak = scanner.check_jwt_weak_secret(valid_token)
    assert finding_weak is not None, "FALLO: se esperaba detectar secreto débil ('secret')"
    print(f"OK: [{finding_weak.severity.value.upper()}] {finding_weak.title}\n")

    print("=== Check 5: enumeración de usuarios ===")
    finding_enum = scanner.check_username_enumeration(
        "http://127.0.0.1:5000/login",
        username_field="username",
        password_field="password",
        existing_username="admin",
        nonexistent_username="no-existe-este-usuario",
    )
    assert finding_enum is not None, "FALLO: se esperaba detectar enumeración de usuarios"
    print(f"OK: [{finding_enum.severity.value.upper()}] {finding_enum.title}")


if __name__ == "__main__":
    main()
