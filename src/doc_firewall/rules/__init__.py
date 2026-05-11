"""Built-in YARA rules package."""
from __future__ import annotations
import os

RULES_DIR = os.path.dirname(__file__)
DOCUMENT_MALWARE_RULES = os.path.join(RULES_DIR, "document_malware.yar")
