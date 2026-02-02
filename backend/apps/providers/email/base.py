# providers/email/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum


class EmailStatus(Enum):
    PENDING = 'pending'
    SENT = 'sent'
    DELIVERED = 'delivered'
    OPENED = 'opened'
    CLICKED = 'clicked'
    BOUNCED = 'bounced'
    FAILED = 'failed'


@dataclass
class EmailResult:
    success: bool
    message_id: Optional[str] = None
    status: EmailStatus = EmailStatus.PENDING
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class BaseEmailProvider(ABC):
    """Abstract base class for Email providers"""
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier"""
        pass

    @abstractmethod
    def send(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        **kwargs
    ) -> EmailResult:
        """Send single email"""
        pass
    
    @abstractmethod
    def send_bulk(
        self,
        recipients: List[Dict[str, str]],  # [{"email": "", "name": ""}, ...]
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        **kwargs
    ) -> List[EmailResult]:
        """Send bulk emails"""
        pass
    
    def validate_email(self, email: str) -> bool:
        """Basic email validation"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))