import logging
import os
import sys

import structlog


def _default_level() -> int:
    """Resolve the default log level.

    Library-quiet by default: importing ``doc_firewall`` must not pollute a
    host application's output, so we default to WARNING. Operators opt into
    more verbosity with ``DOC_FIREWALL_LOG_LEVEL`` (e.g. ``INFO``/``DEBUG``).
    """
    name = os.environ.get("DOC_FIREWALL_LOG_LEVEL", "WARNING").upper()
    return getattr(logging, name, logging.WARNING)


def configure_logger(level: int | None = None, stream=None) -> None:
    """Configure structlog.

    * Logs go to **stderr** — stdout is reserved for machine-readable output
      (``--json`` / ``--siem-format``) so those streams are never corrupted by
      log lines.
    * Level defaults to WARNING (library-quiet); raise it via the ``level``
      argument or the ``DOC_FIREWALL_LOG_LEVEL`` env var.
    """
    if level is None:
        level = _default_level()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        # PrintLoggerFactory writes to stderr — never stdout — so `--json`
        # output stays valid.
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


def get_logger(name: object = None) -> structlog.BoundLogger:
    return structlog.get_logger(name)


# Library-safe default: configure once, quiet (WARNING) and to stderr. An
# embedding application can call configure_logger() again with a different
# level/stream, and the CLI raises the level for interactive use.
if not structlog.is_configured():
    configure_logger()
