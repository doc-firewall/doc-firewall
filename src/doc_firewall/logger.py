import structlog
import logging


def configure_logger():
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


def get_logger(name=None):
    return structlog.get_logger(name)


# Auto-configure on import? Better to call explicitly in main/app setup.
# But for library usage, we can provide a default.
if not structlog.is_configured():
    configure_logger()
