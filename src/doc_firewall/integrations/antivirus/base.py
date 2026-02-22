from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any


class AntivirusEngine(ABC):
    name: str = "antivirus"

    @abstractmethod
    def scan_file(self, path: str) -> Dict[str, Any]:
        raise NotImplementedError
