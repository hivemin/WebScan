"""
modules/auth_scanner.py

A diferencia de sqli_scanner.py y xss_scanner.py, este módulo NO es un
motor de inyección de payloads. Es una colección de comprobaciones
(checks) independientes sobre el COMPORTAMIENTO y la CONFIGURACIÓN del
sistema de autenticación. Cada check es un método separado que puedes
llamar de forma independiente, porque no todos aplican a todos los
sitios (por ejemplo, no todos usan JWT).

Checks implementados:
    1. check_login_rate_limiting  -> fuerza bruta sin freno
    2. check_session_cookie_flags -> cookies mal configuradas
    3. check_jwt_alg_none         -> el servidor acepta JWT sin firma
    4. check_jwt_weak_secret      -> el JWT está firmado con un secreto trivial
    5. check_username_enumeration -> mensajes de error que filtran
                                      si un usuario existe o no
"""

import time
import logging
import statistics
from typing import Optional, List
from dataclasses import dataclass

import jwt as pyjwt  # PyJWT

from core.http_client import HttpClient
from core.findings import Finding, Severity, Confidence
from payloads.weak_jwt_secrets import COMMON_WEAK_JWT_SECRETS

logger = logging.getLogger("audit_tool.auth")


class AuthScanner:
    def __init__(self, client: HttpClient):
        self.client = client

    # ------------------------------------------------------------------
    # Check 1: Rate limiting en login
    # ------------------------------------------------------------------
    def check_login_rate_limiting(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username_value: str,
        num_attempts: int = 10,
    ) -> Optional[Finding]:
        """
        Manda varios intentos de login FALLIDOS seguidos (misma
        contraseña incorrecta a propósito) y observa si el servidor
        reacciona de alguna forma:
            - código 429 (Too Many Requests)
            - un mensaje de "cuenta bloqueada" / "demasiados intentos"
            - un incremento notable en el tiempo de respuesta (indicio
              de un delay artificial anti-fuerza-bruta)

        Si NINGUNA de estas señales aparece tras num_attempts intentos,
        lo marcamos como vulnerable: significa que se podría automatizar
        un ataque de fuerza bruta sin restricción.

        Nota de responsabilidad: num_attempts es deliberadamente bajo
        (10 por defecto). El objetivo es *detectar ausencia de control*,
        no realizar un ataque de fuerza bruta real. No usamos
        diccionarios de contraseñas reales aquí.
        """
        response_times = []
        blocked_signals = ["too many", "locked", "bloqueada", "try again later", "rate limit"]

        for i in range(num_attempts):
            result = self.client.post(
                login_url,
                data={username_field: username_value, password_field: f"wrong-password-{i}"},
            )
            if result.error:
                logger.warning("Error de red durante rate-limit check: %s", result.error)
                continue

            response_times.append(result.elapsed)

            if result.status_code == 429:
                return None  # Hay rate limiting -> no es un hallazgo, es lo correcto

            lowered = result.text.lower()
            if any(signal in lowered for signal in blocked_signals):
                return None  # Detecta bloqueo por mensaje -> correcto

        # Si llegamos aquí, ninguna de las N peticiones fue bloqueada.
        # Comprobamos también si al menos hay un delay creciente
        # artificial (algunas apps ralentizan sin devolver 429).
        if len(response_times) >= 2:
            first_half = statistics.mean(response_times[: len(response_times) // 2])
            second_half = statistics.mean(response_times[len(response_times) // 2:])
            delay_growth = second_half / first_half if first_half > 0 else 1.0
        else:
            delay_growth = 1.0

        if delay_growth < 1.5:  # no hay un enlentecimiento significativo
            return Finding(
                module="auth",
                title="Ausencia de rate limiting en login",
                url=login_url,
                parameter=password_field,
                method="POST",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=(
                    f"{num_attempts} intentos de login fallidos consecutivos, "
                    f"ninguno bloqueado (sin 429, sin mensaje de bloqueo, "
                    f"sin enlentecimiento significativo: x{delay_growth:.2f})"
                ),
                payload=None,
                description=(
                    "El endpoint de login no muestra ninguna señal de "
                    "protección contra fuerza bruta tras múltiples intentos "
                    "fallidos consecutivos desde la misma sesión/IP."
                ),
                remediation=(
                    "Implementar rate limiting por IP/usuario (p.ej. "
                    "bloqueo temporal tras 5 intentos fallidos), CAPTCHA "
                    "progresivo, o backoff exponencial. Considerar además "
                    "notificación al usuario legítimo ante intentos "
                    "sospechosos."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Check 2: Flags de cookies de sesión
    # ------------------------------------------------------------------
    def check_session_cookie_flags(
        self,
        url: str,
        cookie_name_hint: Optional[str] = None,
        method: str = "GET",
        data: Optional[dict] = None,
    ) -> List[Finding]:
        """
        Hace una petición a `url` (GET por defecto, pero muchas apps
        solo emiten la cookie de sesión en la respuesta del POST de
        login, así que se puede pasar method="POST" y data={...}) y
        examina las cabeceras Set-Cookie de la respuesta.
        """
        if method.upper() == "POST":
            result = self.client.post(url, data=data or {})
        else:
            result = self.client.get(url)
        findings = []
        if result.error:
            return findings

        set_cookie_headers = self._get_all_set_cookie_headers(result)
        for raw_cookie in set_cookie_headers:
            name = raw_cookie.split("=")[0].strip()
            if cookie_name_hint and cookie_name_hint.lower() not in name.lower():
                continue

            lowered = raw_cookie.lower()
            missing_flags = []
            if "httponly" not in lowered:
                missing_flags.append("HttpOnly")
            if "secure" not in lowered:
                missing_flags.append("Secure")
            if "samesite" not in lowered:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append(
                    Finding(
                        module="auth",
                        title=f"Cookie de sesión '{name}' sin flags de seguridad",
                        url=url,
                        parameter=name,
                        method="GET",
                        severity=Severity.MEDIUM if "HttpOnly" in missing_flags else Severity.LOW,
                        confidence=Confidence.HIGH,
                        evidence=raw_cookie,
                        payload=None,
                        description=(
                            f"La cookie '{name}' se emite sin: {', '.join(missing_flags)}. "
                            f"Sin HttpOnly, es accesible desde JavaScript (robable vía XSS). "
                            f"Sin Secure, puede viajar en texto plano por HTTP. "
                            f"Sin SameSite, es más vulnerable a CSRF."
                        ),
                        remediation=(
                            "Configurar la cookie de sesión con "
                            "Set-Cookie: ...; HttpOnly; Secure; SameSite=Strict "
                            "(o Lax según necesidades de navegación cross-site)."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _get_all_set_cookie_headers(result) -> List[str]:
        # RequestResult.headers es un dict simple (headers.py en
        # http_client.py usa dict(resp.headers) de requests, que
        # colapsa cabeceras repetidas en una sola string separada por
        # coma en algunos casos). Para Set-Cookie múltiples, lo más
        # fiable sería acceder a response.raw o a la lista completa;
        # aquí trabajamos con lo que tenemos disponible en headers.
        cookie_header = result.headers.get("Set-Cookie", "")
        if not cookie_header:
            return []
        return [cookie_header]  # simplificado; ver nota en README de limitaciones

    # ------------------------------------------------------------------
    # Check 3: JWT con alg=none aceptado por el servidor
    # ------------------------------------------------------------------
    def check_jwt_alg_none(self, protected_url: str, valid_token: str, auth_header_name: str = "Authorization") -> Optional[Finding]:
        """
        Toma un JWT válido (que tú le pasas, obtenido de un login
        legítimo tuyo), le decodifica el payload SIN verificar firma
        (porque solo queremos leer los claims), y genera una versión
        alternativa con:
            - header: {"alg": "none", "typ": "JWT"}
            - misma payload
            - sin firma

        Si el servidor ACEPTA ese token manipulado en un endpoint
        protegido (responde 200 en vez de 401/403), es una
        vulnerabilidad crítica: cualquiera puede fabricar un token
        válido para cualquier usuario sin conocer ningún secreto.
        """
        try:
            payload = pyjwt.decode(valid_token, options={"verify_signature": False})
        except Exception as e:
            logger.warning("No se pudo decodificar el JWT proporcionado: %s", e)
            return None

        forged_token = pyjwt.encode(payload, key="", algorithm="none")
        # PyJWT antiguo puede requerir manejo especial para alg=none;
        # si tu versión lo bloquea, hazlo manualmente con base64 (ver
        # README de este módulo para el fallback manual).

        result = self.client.get(protected_url, headers={auth_header_name: f"Bearer {forged_token}"})
        if result.error:
            return None

        if result.status_code == 200:
            return Finding(
                module="auth",
                title="JWT con alg=none aceptado por el servidor",
                url=protected_url,
                parameter=auth_header_name,
                method="GET",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=f"Token forjado aceptado (HTTP {result.status_code}): {forged_token}",
                payload=forged_token,
                description=(
                    "El servidor acepta tokens JWT con alg=none (sin firma), "
                    "lo que permite a cualquiera fabricar un token válido "
                    "para cualquier usuario/claim, sin conocer ningún "
                    "secreto ni clave privada."
                ),
                remediation=(
                    "Al verificar JWT, especificar explícitamente los "
                    "algoritmos permitidos (p.ej. algorithms=['HS256']) y "
                    "rechazar cualquier token cuyo header indique un "
                    "algoritmo distinto. Nunca confiar en el campo 'alg' "
                    "del propio token para decidir cómo verificarlo."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Check 4: JWT firmado con secreto débil
    # ------------------------------------------------------------------
    def check_jwt_weak_secret(self, token: str) -> Optional[Finding]:
        """
        Intenta verificar la firma del JWT localmente (sin hacer
        peticiones de red) probando una lista corta de secretos
        triviales. Si alguno funciona, el JWT está firmado con un
        secreto adivinable.
        """
        for candidate_secret in COMMON_WEAK_JWT_SECRETS:
            try:
                pyjwt.decode(token, key=candidate_secret, algorithms=["HS256"])
                # Si no lanza excepción, la firma es válida con este secreto.
                return Finding(
                    module="auth",
                    title="JWT firmado con secreto débil/trivial",
                    url="(verificación local, sin endpoint específico)",
                    parameter=None,
                    method="N/A",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    evidence=f"El secreto '{candidate_secret}' verifica correctamente la firma del token",
                    payload=None,
                    description=(
                        "El token JWT está firmado con un secreto trivial "
                        "presente en listas de valores comunes/por defecto. "
                        "Cualquiera puede forjar tokens válidos usando ese "
                        "mismo secreto."
                    ),
                    remediation=(
                        "Usar un secreto largo y aleatorio (mínimo 256 bits "
                        "de entropía para HS256), gestionado como secreto "
                        "de infraestructura (vault/env var), nunca hardcodeado "
                        "ni copiado de ejemplos de documentación."
                    ),
                )
            except pyjwt.InvalidSignatureError:
                continue
            except Exception as e:
                logger.debug("Error probando secreto candidato: %s", e)
                continue
        return None

    # ------------------------------------------------------------------
    # Check 5: Enumeración de usuarios vía mensajes de error
    # ------------------------------------------------------------------
    def check_username_enumeration(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        existing_username: str,
        nonexistent_username: str,
    ) -> Optional[Finding]:
        """
        Compara la respuesta de login con:
            a) un usuario que SÍ existe + contraseña incorrecta
            b) un usuario que NO existe + contraseña incorrecta

        Si el status code o el cuerpo del mensaje difieren de forma
        clara entre (a) y (b), un atacante puede usar el endpoint de
        login como "oráculo" para enumerar qué cuentas existen.

        Requiere que TÚ le indiques un username que sabes que existe
        (p.ej. el tuyo propio en un entorno de prueba) — el scanner no
        adivina usuarios válidos por sí mismo, eso sería otra clase de
        ataque que esta herramienta no realiza.
        """
        result_existing = self.client.post(
            login_url,
            data={username_field: existing_username, password_field: "wrong-password-check"},
        )
        result_nonexistent = self.client.post(
            login_url,
            data={username_field: nonexistent_username, password_field: "wrong-password-check"},
        )

        if result_existing.error or result_nonexistent.error:
            return None

        status_differs = result_existing.status_code != result_nonexistent.status_code
        body_differs = result_existing.text.strip() != result_nonexistent.text.strip()

        if status_differs or body_differs:
            return Finding(
                module="auth",
                title="Enumeración de usuarios vía mensajes de login",
                url=login_url,
                parameter=username_field,
                method="POST",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=(
                    f"Usuario existente -> HTTP {result_existing.status_code}; "
                    f"Usuario inexistente -> HTTP {result_nonexistent.status_code}; "
                    f"cuerpos {'distintos' if body_differs else 'iguales'}"
                ),
                payload=None,
                description=(
                    "El endpoint de login responde de forma distinguible "
                    "según si el usuario existe o no, lo que permite a un "
                    "atacante enumerar cuentas válidas probando muchos "
                    "nombres de usuario."
                ),
                remediation=(
                    "Devolver siempre el mismo mensaje genérico "
                    "('usuario o contraseña incorrectos') y el mismo "
                    "status code, independientemente de si el usuario "
                    "existe. Igualar también el tiempo de respuesta si es "
                    "posible, para evitar enumeración por timing."
                ),
            )
        return None
