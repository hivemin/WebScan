"""

Modelo de datos común para que todos los módulos (sqli, xss, auth)
reporten hallazgos de forma consistente y report.py pueda generar
un informe unificado.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"           # heurística débil, revisar manualmente
    MEDIUM = "medium"     # varios indicios coincidentes
    HIGH = "high"         # evidencia directa (p.ej. error de BD volcado)


@dataclass
class Finding:
    module: str                 # "sqli", "xss", "auth"
    title: str
    url: str
    parameter: Optional[str]
    method: str
    severity: Severity
    confidence: Confidence
    evidence: str                # fragmento de respuesta / payload que disparó la detección
    payload: Optional[str] = None
    description: str = ""
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d
