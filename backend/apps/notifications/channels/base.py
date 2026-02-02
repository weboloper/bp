# notifications/channels/base.py

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from notifications.models import OutboundMessage, Notification


class BaseChannel(ABC):
    """Abstract base class for notification channels"""
    
    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Channel identifier"""
        pass
    
    @abstractmethod
    def send(
        self,
        recipient: Any,
        content: Dict[str, str],
        sent_by=None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send notification through this channel

        Args:
            recipient: Phone number, email, or User instance
            content: Rendered template content
            sent_by: User who triggered (optional)

        Returns:
            Dict with success status and details
        """
        pass
    
    def validate_recipient(self, recipient: Any) -> bool:
        """Validate recipient format"""
        return True