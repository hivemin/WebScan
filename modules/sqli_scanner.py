"""
modules/sqli_scanner.py

Detección de SQL Injection sobre parámetros GET/POST, con tres técnicas:

1. Error-based: inyectar caracteres que rompan la sintaxis SQL y buscar
   mensajes de error de bases de datos conocidos en la respuesta.
2. Boolean-based blind: comparar la respuesta a una condición TRUE vs
   una condición FALSE inyectada; si el contenido cambia de forma
   consistente, hay inyección aunque no haya error visible.
3. Time-based blind: inyectar una condición que fuerce un retraso
   (p.ej. SLEEP) solo si la condición es verdadera, y medir el tiempo
   de respuesta contra una petición baseline.

Diseño: cada técnica es independiente y se puede activar/desactivar.
Todas devuelven objetos Finding (core/findings.py) para que el
reporte sea uniforme entre módulos.

Nota de alcance: este módulo asume que ya se comprobó core/scope.py
antes de llegar aquí. No lo vuelve a comprobar por diseño (single
responsibility) — es responsabilidad del orquestador (cli.py).
"""

import re
import statistics
import logging
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

from core.http_client import HttpClient, RequestResult
from core.findings import Finding, Severity, Confidence

logger = logging.getLogger("audit_tool.sqli")

# Firmas de error de motores de BD comunes. Lista no exhaustiva a propósito:
# el objetivo es cubrir los motores más comunes (MySQL, PostgreSQL, MSSQL,
# Oracle, SQLite) sin convertir esto en una base de datos de fingerprinting.
DB_ERROR_SIGNATURES = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysqlclient\.",
        r"unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"postgresql.*error",
        r"unterminated quoted string",
    ],
    "MSSQL": [
        r"microsoft ole db provider for sql server",
        r"unclosed quotation mark",
        r"microsoft odbc sql server driver",
    ],
    "Oracle": [
        r"ora-\d{5}",
    ],
    "SQLite": [
        r"sqlite3\.OperationalError",
        r"sqlite syntax error",
    ],
}

# Payloads mínimos para *detección*, no para explotación. El objetivo es
# provocar un cambio observable (error, cambio de contenido, o delay),
# no extraer datos.
ERROR_BASED_PAYLOADS = ["'", "\"", "')", "\";", "`"]

# Pares (true_payload, false_payload) para boolean-blind.
# El patrón clásico: comparar "1=1" (siempre cierto) contra "1=2" (siempre falso)
# inyectado junto al valor original del parámetro.
BOOLEAN_PAIRS = [
    (" OR '1'='1", " OR '1'='2"),
    (" AND 1=1", " AND 1=2"),
]

# Payloads de time-blind por motor (SLEEP/WAITFOR/pg_sleep).
TIME_BASED_PAYLOADS = {
    "MySQL": "' OR SLEEP({delay})-- -",
    "PostgreSQL": "'; SELECT pg_sleep({delay})-- -",
    "MSSQL": "'; WAITFOR DELAY '0:0:{delay}'-- -",
}


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


class SqliScanner:
    def __init__(
        self,
        client: HttpClient,
        enable_error_based: bool = True,
        enable_boolean_blind: bool = True,
        enable_time_blind: bool = True,
        time_delay_sec: int = 5,
        boolean_similarity_threshold: float = 0.95,
    ):
        self.client = client
        self.enable_error_based = enable_error_based
        self.enable_boolean_blind = enable_boolean_blind
        self.enable_time_blind = enable_time_blind
        self.time_delay_sec = time_delay_sec
        self.boolean_similarity_threshold = boolean_similarity_threshold

    # ------------------------------------------------------------------
    # Orquestación
    # ------------------------------------------------------------------
    def scan_url(self, url: str, method: str = "GET", body: Optional[dict] = None) -> List[Finding]:
        findings: List[Finding] = []
        params = _extract_params(url, body)

        if not params:
            logger.debug("Sin parámetros que probar en %s", url)
            return findings

        for param in params:
            if self.enable_error_based:
                f = self._test_error_based(url, method, param, body)
                if f:
                    findings.append(f)
                    continue  # si ya hay error-based confirmado, no hace falta seguir con blind

            if self.enable_boolean_blind:
                f = self._test_boolean_blind(url, method, param, body)
                if f:
                    findings.append(f)
                    continue

            if self.enable_time_blind:
                f = self._test_time_blind(url, method, param, body)
                if f:
                    findings.append(f)

        return findings

    # ------------------------------------------------------------------
    # Técnica 1: Error-based
    # ------------------------------------------------------------------
    def _test_error_based(self, url, method, param: Param, body) -> Optional[Finding]:
        for payload in ERROR_BASED_PAYLOADS:
            test_value = param.value + payload
            result = self._send(url, method, param, test_value, body)
            if result.error or not result.text:
                continue

            db_engine, matched = self._match_db_error(result.text)
            if db_engine:
                return Finding(
                    module="sqli",
                    title=f"Posible SQL Injection (error-based, {db_engine})",
                    url=result.url,
                    parameter=param.name,
                    method=method,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=matched,
                    payload=payload,
                    description=(
                        f"El parámetro '{param.name}' provocó un mensaje de error "
                        f"de {db_engine} al inyectar '{payload}'. Esto sugiere que "
                        f"el input se concatena directamente en una consulta SQL "
                        f"sin sanitizar."
                    ),
                    remediation=(
                        "Usar consultas parametrizadas / prepared statements. "
                        "No construir SQL por concatenación de strings. "
                        "Desactivar mensajes de error detallados en producción."
                    ),
                )
        return None

    @staticmethod
    def _match_db_error(text: str):
        lowered = text.lower()
        for engine, patterns in DB_ERROR_SIGNATURES.items():
            for pattern in patterns:
                match = re.search(pattern, lowered, re.IGNORECASE)
                if match:
                    start = max(match.start() - 30, 0)
                    end = min(match.end() + 30, len(text))
                    return engine, text[start:end]
        return None, None

    # ------------------------------------------------------------------
    # Técnica 2: Boolean-based blind
    # ------------------------------------------------------------------
    def _test_boolean_blind(self, url, method, param: Param, body) -> Optional[Finding]:
        baseline = self._send(url, method, param, param.value, body)
        if baseline.error:
            return None

        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_result = self._send(url, method, param, param.value + true_payload, body)
            false_result = self._send(url, method, param, param.value + false_payload, body)
            if true_result.error or false_result.error:
                continue

            sim_true_baseline = self._similarity(baseline.text, true_result.text)
            sim_true_false = self._similarity(true_result.text, false_result.text)

            # Firma esperada de inyección real:
            #   - la respuesta TRUE se parece a la baseline (la condición
            #     original sigue cumpliéndose)
            #   - la respuesta FALSE es notablemente distinta (la condición
            #     inyectada rompe el resultado)
            if (
                sim_true_baseline >= self.boolean_similarity_threshold
                and sim_true_false < self.boolean_similarity_threshold
            ):
                return Finding(
                    module="sqli",
                    title="Posible SQL Injection (boolean-based blind)",
                    url=true_result.url,
                    parameter=param.name,
                    method=method,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        f"similitud TRUE vs baseline={sim_true_baseline:.2f}, "
                        f"similitud TRUE vs FALSE={sim_true_false:.2f}"
                    ),
                    payload=f"TRUE='{true_payload}' / FALSE='{false_payload}'",
                    description=(
                        f"El parámetro '{param.name}' devuelve contenido distinto "
                        f"según si la condición inyectada es verdadera o falsa, "
                        f"sin mostrar un error SQL explícito. Indicio de blind SQLi."
                    ),
                    remediation=(
                        "Usar consultas parametrizadas. Validar y tipar el input "
                        "esperado (p.ej. si se espera un entero, forzar cast/int)."
                    ),
                )
        return None

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        # Similaridad simple basada en longitud + solapamiento de líneas.
        # Suficiente para detección; no pretende ser un diff semántico.
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        len_ratio = min(len(a), len(b)) / max(len(a), len(b))
        lines_a, lines_b = set(a.splitlines()), set(b.splitlines())
        if lines_a or lines_b:
            overlap = len(lines_a & lines_b) / max(len(lines_a | lines_b), 1)
        else:
            overlap = 1.0
        return (len_ratio + overlap) / 2

    # ------------------------------------------------------------------
    # Técnica 3: Time-based blind
    # ------------------------------------------------------------------
    def _test_time_blind(self, url, method, param: Param, body) -> Optional[Finding]:
        # Baseline: varias peticiones normales para tener una noción de
        # latencia "normal" y evitar falsos positivos por red lenta.
        baseline_times = []
        for _ in range(3):
            r = self._send(url, method, param, param.value, body)
            if r.error:
                return None
            baseline_times.append(r.elapsed)
        baseline_median = statistics.median(baseline_times)

        for engine, template in TIME_BASED_PAYLOADS.items():
            payload = template.format(delay=self.time_delay_sec)
            result = self._send(url, method, param, param.value + payload, body)
            if result.error:
                continue

            # El delay observado debe acercarse al delay pedido, y ser
            # claramente mayor que el baseline (con margen).
            expected_min = baseline_median + (self.time_delay_sec * 0.8)
            if result.elapsed >= expected_min:
                # Confirmar con una segunda petición para reducir falsos
                # positivos por jitter de red puntual.
                confirm = self._send(url, method, param, param.value + payload, body)
                if confirm.error or confirm.elapsed < expected_min:
                    continue

                return Finding(
                    module="sqli",
                    title=f"Posible SQL Injection (time-based blind, {engine})",
                    url=result.url,
                    parameter=param.name,
                    method=method,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        f"baseline={baseline_median:.2f}s, "
                        f"con payload={result.elapsed:.2f}s / {confirm.elapsed:.2f}s "
                        f"(delay pedido={self.time_delay_sec}s)"
                    ),
                    payload=payload,
                    description=(
                        f"El parámetro '{param.name}' provoca un retraso en la "
                        f"respuesta consistente con la ejecución de un SLEEP/WAITFOR "
                        f"inyectado, replicado en dos peticiones."
                    ),
                    remediation=(
                        "Usar consultas parametrizadas. Limitar el tiempo de "
                        "ejecución de queries a nivel de BD. Monitorizar queries "
                        "con duración anómala."
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # Helper de envío
    # ------------------------------------------------------------------
    def _send(self, url, method, param: Param, test_value: str, body) -> RequestResult:
        if param.location == "query":
            test_url = _inject_query_param(url, param.name, test_value)
            if method.upper() == "GET":
                return self.client.get(test_url)
            return self.client.post(test_url, data=body or {})
        else:
            new_body = dict(body or {})
            new_body[param.name] = test_value
            return self.client.post(url, data=new_body)
