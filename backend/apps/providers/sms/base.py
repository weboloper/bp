# providers/sms/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum


class SMSStatus(Enum):
    PENDING = 'pending'
    SENT = 'sent'
    DELIVERED = 'delivered'
    FAILED = 'failed'
    REJECTED = 'rejected'


@dataclass
class SMSResult:
    success: bool
    message_id: Optional[str] = None
    status: SMSStatus = SMSStatus.PENDING
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    credits_used: int = 1
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class BulkSMSResult:
    success: bool
    batch_id: Optional[str] = None
    total: int = 0
    successful: int = 0
    failed: int = 0
    credits_used: int = 0
    results: List[SMSResult] = None
    error_message: Optional[str] = None


class BaseSMSProvider(ABC):
    """Abstract base class for SMS providers"""
    
    TURKISH_CHARS = set('çÇğĞıİöÖşŞüÜ')
    GSM7_SINGLE_LIMIT = 160
    GSM7_CONCAT_LIMIT = 153
    UCS2_SINGLE_LIMIT = 70
    UCS2_CONCAT_LIMIT = 67
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier"""
        pass
    
    @abstractmethod
    def send(self, phone: str, message: str, sender_id: Optional[str] = None) -> SMSResult:
        """Send single SMS"""
        pass
    
    @abstractmethod
    def send_bulk(self, recipients: List[str], message: str, sender_id: Optional[str] = None) -> BulkSMSResult:
        """Send bulk SMS"""
        pass
    
    @abstractmethod
    def get_delivery_report(self, message_id: str) -> SMSResult:
        """Get delivery status"""
        pass
    
    @abstractmethod
    def get_balance(self) -> Dict[str, Any]:
        """Get account balance"""
        pass
    
    def calculate_credits(self, message: str) -> int:
        """Calculate SMS credits needed"""
        length = len(message)
        has_turkish = bool(self.TURKISH_CHARS.intersection(set(message)))
        
        if has_turkish:
            if length <= self.UCS2_SINGLE_LIMIT:
                return 1
            return (length + self.UCS2_CONCAT_LIMIT - 1) // self.UCS2_CONCAT_LIMIT
        else:
            if length <= self.GSM7_SINGLE_LIMIT:
                return 1
            return (length + self.GSM7_CONCAT_LIMIT - 1) // self.GSM7_CONCAT_LIMIT
    
    def normalize_phone(self, phone: str) -> str:
        """Normalize phone to 10 digits"""
        import re
        digits = re.sub(r'\D', '', phone)
        if digits.startswith('90') and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith('0') and len(digits) == 11:
            digits = digits[1:]
        return digits
    
    def validate_phone(self, phone: str) -> bool:
        """Validate Turkish mobile number"""
        normalized = self.normalize_phone(phone)
        return len(normalized) == 10 and normalized.startswith('5')