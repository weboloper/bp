# notifications/channels/__init__.py

from typing import TYPE_CHECKING
from notifications.constants import Channel

if TYPE_CHECKING:
    from .base import BaseChannel


def get_channel(channel: str) -> 'BaseChannel':
    """
    Factory function - Returns channel instance
    """
    if channel == Channel.SMS:
        from .sms import SMSChannel
        return SMSChannel()
    elif channel == Channel.EMAIL:
        from .email import EmailChannel
        return EmailChannel()
    elif channel == Channel.IN_APP:
        from .in_app import InAppChannel
        return InAppChannel()
    elif channel == Channel.PUSH:
        raise NotImplementedError("Push channel not implemented yet")
    else:
        raise ValueError(f"Unknown channel: {channel}")


from .base import BaseChannel
from .sms import SMSChannel
from .email import EmailChannel
from .in_app import InAppChannel

__all__ = [
    'get_channel',
    'BaseChannel',
    'SMSChannel',
    'EmailChannel',
    'InAppChannel',
]