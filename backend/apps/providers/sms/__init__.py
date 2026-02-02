# providers/sms/__init__.py

from .base import BaseSMSProvider, SMSResult, BulkSMSResult, SMSStatus


def get_sms_provider() -> BaseSMSProvider:
    """
    Factory function - Returns active SMS provider based on settings.

    Uses SMS_PROVIDER setting to determine which backend to use.
    """
    from providers.registry import get_sms_backend
    return get_sms_backend()


__all__ = [
    'get_sms_provider',
    'BaseSMSProvider',
    'SMSResult',
    'BulkSMSResult',
    'SMSStatus',
]
