from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ParsedDocument:
    file_path: str
    file_type: str
    text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    pdf: Optional[Dict[str, Any]] = None
    docx: Optional[Dict[str, Any]] = None
