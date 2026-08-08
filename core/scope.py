"""
Control de alcance (scope) y autorización.

La herramienta se niega a escanear un host si no está declarado en
scope.yaml con authorized: true. Esto es intencional: obliga a que
quien use la herramienta deje constancia explícita de que tiene
permiso para auditar ese objetivo (propio, de cliente con contrato, o
entorno de práctica).
"""

import sys
import yaml
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List


@dataclass
class ScopeEntry:
    host: str
    authorized: bool
    note: str = ""


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, entries: List[ScopeEntry]):
        self.entries = {e.host.lower(): e for e in entries}

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        entries = [
            ScopeEntry(
                host=item["host"],
                authorized=bool(item.get("authorized", False)),
                note=item.get("note", ""),
            )
            for item in data.get("targets", [])
        ]
        return cls(entries)

    def check(self, url: str) -> None:
        host = urlparse(url).hostname
        if not host:
            raise ScopeError(f"No se pudo determinar el host de: {url}")

        entry = self.entries.get(host.lower())
        if entry is None:
            raise ScopeError(
                f"'{host}' no está declarado en scope.yaml. "
                f"Añádelo con authorized: true solo si tienes permiso explícito "
                f"para auditarlo."
            )
        if not entry.authorized:
            raise ScopeError(
                f"'{host}' está en scope.yaml pero authorized: false. "
                f"Escaneo bloqueado."
            )


def require_scope_confirmation(scope_path: str, target_url: str) -> Scope:
    """
    Punto de entrada usado por cli.py. Lanza SystemExit con mensaje claro
    si el target no está autorizado, en vez de dejar que el escaneo siga.
    """
    try:
        scope = Scope.load(scope_path)
        scope.check(target_url)
        return scope
    except FileNotFoundError:
        print(
            f"[!] No se encontró {scope_path}. Crea uno (ver scope.example.yaml) "
            f"declarando el target como authorized: true antes de escanear."
        )
        sys.exit(1)
    except ScopeError as e:
        print(f"[!] Escaneo bloqueado: {e}")
        sys.exit(1)
