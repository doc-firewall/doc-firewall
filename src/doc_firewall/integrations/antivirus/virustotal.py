from __future__ import annotations
import os
import json
import hashlib
from typing import Dict, Any
import urllib.request
import urllib.parse
import urllib.error

from .base import AntivirusEngine
from ...logger import get_logger

logger = get_logger()


class VirusTotalEngine(AntivirusEngine):
    name: str = "virustotal"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        if not self.api_key:
            raise ValueError(
                "VirusTotal API key must be provided or set in VT_API_KEY env var"
            )

    def _calculate_sha256(self, path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, path: str) -> Dict[str, Any]:
        """
        Scans a file using VirusTotal API v3.
        Note: This involves uploading the file or its hash to a third-party service.
        """
        file_hash = self._calculate_sha256(path)

        # 1. Check if file hash exists (fast lookup)
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        if not url.startswith(("http://", "https://")):
            raise ValueError("Invalid URL scheme")
        headers = {"x-apikey": self.api_key}

        try:
            req = urllib.request.Request(url, headers=headers)  # noqa: S310
            with urllib.request.urlopen(req) as response:  # noqa: S310
                if response.status == 200:
                    data = json.loads(response.read())
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    return {
                        "infected": malicious > 0 or suspicious > 0,
                        "metadata": {
                            "engine": "VirusTotal",
                            "positives": malicious,
                            "suspicious": suspicious,
                            "total": stats.get("total", 0),
                            "link": f"https://www.virustotal.com/gui/file/{file_hash}",
                        },
                    }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # File not known, needs upload.
                # For this demo, we treat 'unknown' as clean or raise warning.
                # Implementing full upload flow is complex (get upload URL
                # -> post file -> poll analysis).
                logger.warning("File hash not found in VirusTotal", hash=file_hash)
                return {
                    "infected": False,
                    "inconclusive": True,
                    "metadata": {"error": "File unknown to VirusTotal"},
                }
            logger.error("VirusTotal API error", code=e.code)
            raise e

        except Exception as e:
            logger.error("VirusTotal scan failed", error=str(e))
            raise e

        return {"infected": False}
