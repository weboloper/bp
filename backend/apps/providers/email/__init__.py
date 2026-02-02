# providers/email/__init__.py

from .base import BaseEmailProvider, EmailResult, EmailStatus


def get_email_provider() -> BaseEmailProvider:
    """
    Factory function - Returns active Email provider based on settings.

    Uses EMAIL_PROVIDER setting to determine which backend to use.
    """
    from providers.registry import get_email_backend
    return get_email_backend()


__all__ = [
    'get_email_provider',
    'BaseEmailProvider',
    'EmailResult',
    'EmailStatus',
]
