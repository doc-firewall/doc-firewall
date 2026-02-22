from __future__ import annotations
import os


def guess_file_type(path: str) -> str:
    ext = os.path.splitext(path.lower())[1]
    if ext == ".pdf":
        return "pdf"
    if ext in [".docx", ".docm"]:
        return "docx"
    return "unknown"
