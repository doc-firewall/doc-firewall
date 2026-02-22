from __future__ import annotations
from typing import Optional
from ...config import ScanConfig
from .base import AntivirusEngine
from .clamav import ClamAVEngine
from .virustotal import VirusTotalEngine
from .generic_cli import GenericCLIEngine
from ...logger import get_logger

logger = get_logger()


class AntivirusFactory:
    """
    Factory to instantiate Antivirus Engines based on configuration.
    """

    @staticmethod
    def create(config: ScanConfig) -> Optional[AntivirusEngine]:
        provider = config.antivirus.provider.lower()

        if provider == "clamav":
            return ClamAVEngine(
                clamscan_path=config.antivirus.clamav_bin_path,
                host=config.antivirus.clamav_host,
                port=config.antivirus.clamav_port,
                socket_path=config.antivirus.clamav_socket_path,
            )

        elif provider == "virustotal":
            if not config.antivirus.virustotal_api_key:
                logger.warning(
                    "VirusTotal enabled but no API key provided. Antivirus disabled."
                )
                return None
            return VirusTotalEngine(api_key=config.antivirus.virustotal_api_key)

        elif provider == "generic_cli":
            if not config.antivirus.generic_cli_command:
                logger.warning(
                    "Generic CLI provider selected but 'generic_cli_command' is empty."
                )
                return None
            return GenericCLIEngine(
                command_template=config.antivirus.generic_cli_command,
                infected_exit_codes=config.antivirus.generic_cli_infected_codes,
            )

        else:
            logger.warning(f"Unknown antivirus provider: {provider}")
            return None
