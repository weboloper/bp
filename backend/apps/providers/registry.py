"""
Provider backend factory.
Settings'den provider seçimini okur, ilgili backend'i döner.
"""
from django.conf import settings
from django.utils.module_loading import import_string


BACKEND_MAP = {
    'email': {
        'smtp': 'providers.email.smtp.SMTPProvider',
        'sendgrid': 'providers.email.sendgrid.SendgridProvider',
        'mock': 'providers.email.mock.MockEmailProvider',
    },
    'sms': {
        'netgsm': 'providers.sms.netgsm.NetGSMProvider',
        'twilio': 'providers.sms.twilio.TwilioProvider',
        'mock': 'providers.sms.mock.MockSMSProvider',
    }
}


def get_email_backend():
    """
    Get email backend based on EMAIL_PROVIDER setting.

    Returns:
        Email backend instance (SMTPBackend, SendGridBackend, or MockBackend)

    Raises:
        ValueError: If unknown provider specified
    """
    provider = getattr(settings, 'EMAIL_PROVIDER', 'mock')
    backend_path = BACKEND_MAP['email'].get(provider)
    if not backend_path:
        raise ValueError(f"Unknown email provider: {provider}")
    return import_string(backend_path)()


def get_sms_backend():
    """
    Get SMS backend based on SMS_PROVIDER setting.

    Returns:
        SMS backend instance (NetGSMBackend, TwilioBackend, or MockBackend)

    Raises:
        ValueError: If unknown provider specified
    """
    provider = getattr(settings, 'SMS_PROVIDER', 'mock')
    backend_path = BACKEND_MAP['sms'].get(provider)
    if not backend_path:
        raise ValueError(f"Unknown SMS provider: {provider}")
    return import_string(backend_path)()
