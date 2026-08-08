"""

Wrapper sobre requests que centraliza:
- Gestión de sesión (cookies, headers, auth)
- Rate limiting (para no tumbar el servidor objetivo)
- Logging de todas las peticiones/respuestas (auditoría del propio escaneo)
- Reintentos controlados

Todos los módulos de detección (sqli, xss, auth) deben usar este cliente
en lugar de `requests` directamente.
"""

import time
import logging
from dataclasses import dataclass
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("audit_tool.http_client")


@dataclass
class RequestResult:
    url: str
    method: str
    status_code: Optional[int]
    elapsed: float          # segundos, útil para time-based blind SQLi
    text: str
    headers: dict
    error: Optional[str] = None


class HttpClient:
    def __init__(
        self,
        base_headers: Optional[dict] = None,
        rate_limit_per_sec: float = 5.0,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
    ):
        self.session = requests.Session()
        self.session.headers.update(
            base_headers
            or {
                "User-Agent": "web-audit-tool/0.1 (authorized-scan)",
            }
        )
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec > 0 else 0
        self._last_request_ts = 0.0

    def _throttle(self):
        elapsed_since_last = time.monotonic() - self._last_request_ts
        wait = self.min_interval - elapsed_since_last
        if wait > 0:
            time.sleep(wait)
        self._last_request_ts = time.monotonic()

    def request(self, method: str, url: str, **kwargs) -> RequestResult:
        self._throttle()
        start = time.monotonic()
        try:
            resp = self.session.request(
                method, url, timeout=self.timeout, verify=self.verify_ssl, **kwargs
            )
            elapsed = time.monotonic() - start
            logger.debug("%s %s -> %s (%.3fs)", method, url, resp.status_code, elapsed)
            return RequestResult(
                url=url,
                method=method,
                status_code=resp.status_code,
                elapsed=elapsed,
                text=resp.text,
                headers=dict(resp.headers),
            )
        except requests.RequestException as e:
            elapsed = time.monotonic() - start
            logger.warning("%s %s -> ERROR %s", method, url, e)
            return RequestResult(
                url=url,
                method=method,
                status_code=None,
                elapsed=elapsed,
                text="",
                headers={},
                error=str(e),
            )

    def get(self, url, **kwargs) -> RequestResult:
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs) -> RequestResult:
        return self.request("POST", url, **kwargs)
