"""
payloads/weak_jwt_secrets.py

Lista MUY reducida de secretos triviales usados para comprobar si un
JWT está firmado con algo trivialmente adivinable.

"""

COMMON_WEAK_JWT_SECRETS = [
    "secret",
    "123456",
    "password",
    "your-256-bit-secret",  # valor de ejemplo del propio debugger de jwt.io
    "changeme",
    "jwt_secret",
    "supersecret",
]
