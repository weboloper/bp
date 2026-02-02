"""
Mock SMS Provider - For development and testing

Does not send real SMS, just logs and returns success.
"""
import logging
import uuid
from typing import List, Dict, Any, Optional

from .base import BaseSMSProvider, SMSResult, BulkSMSResult, SMSStatus

logger = logging.getLogger(__name__)


class MockSMSProvider(BaseSMSProvider):
    """
    Mock SMS Provider for development and testing.

    Features:
    - Logs all SMS operations
    - Always returns success (configurable)
    - Simulates credits calculation
    - Can simulate failures for testing
    """

    @property
    def provider_name(self) -> str:
        return 'mock'

    def __init__(
        self,
        simulate_failures: bool = False,
        failure_rate: float = 0.0,
        sender_id: Optional[str] = None
    ):
        """
        Initialize Mock provider.

        Args:
            simulate_failures: If True, randomly fail some sends
            failure_rate: Probability of failure (0.0 to 1.0)
            sender_id: Default sender ID
        """
        self.simulate_failures = simulate_failures
        self.failure_rate = failure_rate
        self.default_sender_id = sender_id or 'SALON'

        # In-memory storage for testing
        self._sent_messages: List[Dict[str, Any]] = []
        self._balance = 10000  # Mock balance

    def send(
        self,
        phone: str,
        message: str,
        sender_id: Optional[str] = None
    ) -> SMSResult:
        """
        Simulate sending SMS (doesn't actually send).
        """
        if not self.validate_phone(phone):
            logger.warning(f"[MOCK SMS] Invalid phone: {phone}")
            return SMSResult(
                success=False,
                status=SMSStatus.FAILED,
                error_code='INVALID_PHONE',
                error_message='Geçersiz telefon numarası'
            )

        # Simulate random failures if configured
        if self.simulate_failures:
            import random
            if random.random() < self.failure_rate:
                logger.info(f"[MOCK SMS] Simulated failure to {phone}")
                return SMSResult(
                    success=False,
                    status=SMSStatus.FAILED,
                    error_code='SIMULATED_FAILURE',
                    error_message='Simulated failure for testing'
                )

        # Generate mock message ID
        message_id = f"MOCK_{uuid.uuid4().hex[:12].upper()}"
        credits = self.calculate_credits(message)

        # Store for testing
        self._sent_messages.append({
            'message_id': message_id,
            'phone': self.normalize_phone(phone),
            'message': message,
            'sender_id': sender_id or self.default_sender_id,
            'credits': credits,
            'status': 'sent'
        })

        logger.info(
            f"[MOCK SMS] Sent to {phone}\n"
            f"  Message ID: {message_id}\n"
            f"  Sender: {sender_id or self.default_sender_id}\n"
            f"  Credits: {credits}\n"
            f"  Message: {message[:50]}{'...' if len(message) > 50 else ''}"
        )

        return SMSResult(
            success=True,
            message_id=message_id,
            status=SMSStatus.SENT,
            credits_used=credits,
            raw_response={'mock': True, 'message_id': message_id}
        )

    def send_bulk(
        self,
        recipients: List[str],
        message: str,
        sender_id: Optional[str] = None
    ) -> BulkSMSResult:
        """
        Simulate bulk SMS sending.
        """
        if not recipients:
            return BulkSMSResult(
                success=False,
                error_message='Alıcı listesi boş'
            )

        batch_id = f"MOCK_BATCH_{uuid.uuid4().hex[:8].upper()}"
        credits_per_msg = self.calculate_credits(message)
        results = []
        successful = 0

        for phone in recipients:
            if self.validate_phone(phone):
                result = self.send(phone, message, sender_id)
                results.append(result)
                if result.success:
                    successful += 1
            else:
                results.append(SMSResult(
                    success=False,
                    status=SMSStatus.FAILED,
                    error_code='INVALID_PHONE',
                    error_message='Geçersiz telefon numarası'
                ))

        logger.info(
            f"[MOCK SMS] Bulk send completed\n"
            f"  Batch ID: {batch_id}\n"
            f"  Total: {len(recipients)}\n"
            f"  Successful: {successful}\n"
            f"  Failed: {len(recipients) - successful}\n"
            f"  Credits: {successful * credits_per_msg}"
        )

        return BulkSMSResult(
            success=successful > 0,
            batch_id=batch_id,
            total=len(recipients),
            successful=successful,
            failed=len(recipients) - successful,
            credits_used=successful * credits_per_msg,
            results=results
        )

    def get_delivery_report(self, message_id: str) -> SMSResult:
        """
        Get simulated delivery status.
        """
        for msg in self._sent_messages:
            if msg['message_id'] == message_id:
                logger.info(f"[MOCK SMS] Delivery report for {message_id}: DELIVERED")
                return SMSResult(
                    success=True,
                    message_id=message_id,
                    status=SMSStatus.DELIVERED,
                    raw_response={'mock': True, 'status': 'delivered'}
                )

        logger.warning(f"[MOCK SMS] Message not found: {message_id}")
        return SMSResult(
            success=False,
            message_id=message_id,
            status=SMSStatus.PENDING,
            error_code='NOT_FOUND',
            error_message='Mesaj bulunamadı'
        )

    def get_balance(self) -> Dict[str, Any]:
        """
        Get simulated balance.
        """
        logger.info(f"[MOCK SMS] Balance check: {self._balance} credits")
        return {
            'success': True,
            'provider': 'mock',
            'balance': self._balance,
            'currency': 'credits',
            'raw_response': {'mock': True}
        }

    # Testing helpers

    def get_sent_messages(self) -> List[Dict[str, Any]]:
        """Get all sent messages (for testing)."""
        return self._sent_messages.copy()

    def clear_sent_messages(self):
        """Clear sent messages history (for testing)."""
        self._sent_messages.clear()

    def set_balance(self, balance: int):
        """Set mock balance (for testing)."""
        self._balance = balance

    def get_last_message(self) -> Optional[Dict[str, Any]]:
        """Get last sent message (for testing)."""
        return self._sent_messages[-1] if self._sent_messages else None
