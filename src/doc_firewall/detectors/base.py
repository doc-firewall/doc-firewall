from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List
from ..config import ScanConfig
from ..report import Finding
from ..analyzers.base import ParsedDocument


class Detector(ABC):
    name: str = "detector"

    @abstractmethod
    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        raise NotImplementedError
