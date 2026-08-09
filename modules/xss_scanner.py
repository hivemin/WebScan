"""
modules/xss_scanner.py

Detección de XSS reflejado.

Estrategia (repaso rápido, detalle completo en payloads/xss_payloads.py):
1. Por cada parámetro del target, generamos un marcador único aleatorio.
2. Probamos varias plantillas de payload (una por contexto HTML/JS/atributo).
3. Buscamos el marcador en la respuesta:
   - Si aparece TAL CUAL (sin escapar) -> vulnerabilidad confirmada.
   - Si aparece ESCAPADO (&lt; en vez de <) -> input reflejado pero
     saneado; lo registramos como INFO, no como vulnerabilidad, para
     que quede constancia de que ese parámetro se refleja (útil para
     revisión manual, pero no es una detección positiva).
   - Si no aparece en absoluto -> el parámetro no se refleja en la
     respuesta; no hay nada que reportar para XSS reflejado.

Nota importante sobre limitaciones: esto SOLO cubre XSS reflejado
(el más fácil de detectar de forma automática, porque la prueba y el
resultado ocurren en la misma petición/respuesta). XSS almacenado
(donde el payload se guarda en BD y se refleja en OTRA petición
posterior, p.ej. un comentario que luego ve otro usuario) requiere un
flujo de dos pasos: inyectar en un punto, y luego visitar otra URL
donde se muestra ese contenido. Dejamos un método
`check_stored_marker` preparado para ese caso, pero requiere que el
usuario de la herramienta indique manualmente el par
"URL donde se inyecta" / "URL donde se refleja", porque no hay forma
genérica de que el scanner adivine esa relación por sí solo.
"""

import re
import html
import random
import string
import logging
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

from core.http_client import HttpClient
from core.findings import Finding, Severity, Confidence
from payloads.xss_payloads import XSS_PAYLOAD_TEMPLATES

logger = logging.getLogger("audit_tool.xss")


@dataclass
class Param:
    name: str
    value: str
    location: str  # "query" o "body"


def _extract_params(url: str, body: Optional[dict] = None) -> List[Param]:
    params = []
    parsed = urlparse(url)
    for k, v in parse_qs(parsed.query).items():
        params.append(Param(name=k, value=v[0] if v else "", location="query"))
    if body:
        for k, v in body.items():
            params.append(Param(name=k, value=str(v), location="body"))
    return params


def _inject_query_param(url: str, param_name: str, new_value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param_name] = new_value
    new_query = urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _generate_marker() -> str:
    return "xss" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


class XssScanner:
    def __init__(self, client: HttpClient):
        self.client = client

    def scan_url(self, url: str, method: str = "GET", body: Optional[dict] = None) -> List[Finding]:
        findings: List[Finding] = []
        params = _extract_params(url, body)

        if not params:
            logger.debug("Sin parámetros que probar en %s", url)
            return findings

        for param in params:
            for template_def in XSS_PAYLOAD_TEMPLATES:
                marker = _generate_marker()
                payload = template_def["template"].format(marker=marker)
                raw_needle = template_def["detect_raw"].format(marker=marker)

                result = self._send(url, method, param, payload, body)
                if result.error or not result.text:
                    continue

                finding = self._analyze_response(
                    response_text=result.text,
                    response_url=result.url,
                    param=param,
                    method=method,
                    payload=payload,
                    marker=marker,
                    raw_needle=raw_needle,
                    context=template_def["context"],
                    explanation=template_def["explanation"],
                )
                if finding:
                    findings.append(finding)

        return findings

    def _analyze_response(
        self,
        response_text: str,
        response_url: str,
        param: Param,
        method: str,
        payload: str,
        marker: str,
        raw_needle: str,
        context: str,
        explanation: str,
    ) -> Optional[Finding]:
        # Caso 1: aparece SIN escapar -> vulnerabilidad confirmada.
        if raw_needle in response_text:
            return Finding(
                module="xss",
                title=f"XSS reflejado confirmado (contexto: {context})",
                url=response_url,
                parameter=param.name,
                method=method,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=self._context_snippet(response_text, raw_needle),
                payload=payload,
                description=(
                    f"El parámetro '{param.name}' refleja el input sin escapar "
                    f"en un contexto de tipo '{context}'. {explanation}"
                ),
                remediation=(
                    "Escapar el output según el contexto (HTML-encode para "
                    "texto/atributos, JS-encode dentro de <script>). Usar el "
                    "auto-escaping del framework/template engine en vez de "
                    "construir HTML manualmente. Considerar una Content-"
                    "Security-Policy como defensa en profundidad."
                ),
            )

        # Caso 2: aparece pero ESCAPADO -> se refleja, pero saneado.
        # Comprobamos si la versión HTML-escapada del marcador aparece.
        escaped_needle = html.escape(raw_needle)
        if escaped_needle in response_text or marker in response_text:
            return Finding(
                module="xss",
                title=f"Input reflejado pero saneado (contexto: {context})",
                url=response_url,
                parameter=param.name,
                method=method,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                evidence=self._context_snippet(response_text, marker),
                payload=payload,
                description=(
                    f"El parámetro '{param.name}' se refleja en la respuesta "
                    f"pero aparenta estar correctamente escapado. No se "
                    f"considera vulnerable, pero se registra por si un "
                    f"revisor humano quiere confirmar manualmente distintos "
                    f"encodings (doble encoding, unicode, etc.)."
                ),
                remediation="Ninguna acción requerida si el escapado es correcto.",
            )

        # Caso 3: no aparece en absoluto -> nada que reportar.
        return None

    @staticmethod
    def _context_snippet(text: str, needle: str, margin: int = 40) -> str:
        idx = text.find(needle)
        if idx == -1:
            return needle
        start = max(idx - margin, 0)
        end = min(idx + len(needle) + margin, len(text))
        return text[start:end]

    def _send(self, url, method, param: Param, test_value: str, body):
        if param.location == "query":
            test_url = _inject_query_param(url, param.name, test_value)
            if method.upper() == "GET":
                return self.client.get(test_url)
            return self.client.post(test_url, data=body or {})
        else:
            new_body = dict(body or {})
            new_body[param.name] = test_value
            return self.client.post(url, data=new_body)

    # ------------------------------------------------------------------
    # XSS almacenado (stored) - flujo manual de dos pasos
    # ------------------------------------------------------------------
    def inject_stored_marker(self, injection_url: str, method: str, param_name: str, body: Optional[dict] = None):
        """
        Paso 1 del flujo stored-XSS: inyecta un marcador único en el
        punto indicado (p.ej. un formulario de comentarios) y devuelve
        el marcador generado para que lo uses en check_stored_marker.

        No intentamos automatizar "encontrar dónde se refleja después"
        porque eso requeriría que el scanner conozca la estructura de
        navegación de la aplicación (¿el comentario aparece en la misma
        página? ¿en un panel de moderación? ¿en el perfil de otro
        usuario?). Esa relación la tiene que indicar quien audita.
        """
        marker = _generate_marker()
        payload = f"<script>/*{marker}*/</script>"
        param = Param(name=param_name, value="", location="body" if body is not None else "query")
        result = self._send(injection_url, method, param, payload, body)
        return marker, payload, result

    def check_stored_marker(self, view_url: str, marker: str, raw_needle: str) -> Optional[Finding]:
        """
        Paso 2: visita la URL donde debería reflejarse el contenido
        inyectado previamente y comprueba si el marcador aparece sin
        escapar.
        """
        result = self.client.get(view_url)
        if result.error or not result.text:
            return None
        if raw_needle in result.text:
            return Finding(
                module="xss",
                title="XSS almacenado confirmado",
                url=view_url,
                parameter=None,
                method="GET",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                evidence=self._context_snippet(result.text, raw_needle),
                payload=raw_needle,
                description=(
                    "El marcador inyectado previamente se refleja sin "
                    "escapar al visitar esta URL, confirmando que el "
                    "payload quedó almacenado y se ejecuta en una vista "
                    "distinta a la de inyección. Severidad crítica porque "
                    "puede afectar a otros usuarios que visiten esta página."
                ),
                remediation=(
                    "Sanear el input tanto al guardar como al mostrar "
                    "(defensa en profundidad). Aplicar CSP estricta."
                ),
            )
        return None
