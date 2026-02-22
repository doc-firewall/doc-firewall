from __future__ import annotations
import subprocess
import shlex
from typing import Dict, Any, List
from .base import AntivirusEngine
from ...logger import get_logger

logger = get_logger()


class GenericCLIEngine(AntivirusEngine):
    name: str = "generic_cli"

    def __init__(self, command_template: str, infected_exit_codes: List[int] = None):
        """
        :param command_template: Command string with {path} placeholder.
                                 Example: "sophos_scan --file {path}"
        :param infected_exit_codes: List of exit codes that indicate infection.
                                    Default [1].
        """
        self.command_template = command_template
        self.infected_exit_codes = infected_exit_codes or [1]

    def scan_file(self, path: str) -> Dict[str, Any]:
        """
        Executes the CLI command.
        """
        # Safe substitution?
        # We manually construct the arg list to avoid shell injection if possible,
        # but the template user provides might contain flags.
        # We'll default to shell=False tokenization if possible, but that's
        # hard with a template string.
        # We'll replace {path} in the string, then shlex.split it.

        # 1. Build command args safely — never interpolate the file path
        #    directly into a format string to prevent argument injection
        try:
            placeholder = "__DOC_FIREWALL_PATH_PLACEHOLDER__"
            cmd_str = self.command_template.format(path=placeholder)
            args = shlex.split(cmd_str)
            args = [path if a == placeholder else a for a in args]
        except (KeyError, ValueError):
            # Template missing {path} — append path as a standalone argument
            args = shlex.split(self.command_template)
            args.append(path)

        try:
            # Run without shell=True for security, unless user explicitly
            # demands (not supported here)
            result = subprocess.run(  # noqa: S603
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,  # 5 minute safety limit
            )

            # Check exit code
            is_infected = result.returncode in self.infected_exit_codes

            return {
                "infected": is_infected,
                "metadata": {
                    "engine": "GenericCLI",
                    "command": args[0],
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:500],  # truncate
                    "stderr": result.stderr[:500],
                },
            }

        except FileNotFoundError:
            logger.error("Antivirus binary not found", command=args[0])
            return {
                "infected": False,
                "error": f"Command not found: {args[0]}",
                "metadata": {"error": "Binary missing"},
            }
        except Exception as e:
            logger.error("Generic CLI scan error", error=str(e))
            raise e
