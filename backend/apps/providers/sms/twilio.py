"""
Twilio SMS Provider - International SMS gateway

API Documentation: https://www.twilio.com/docs/sms

This is a placeholder implementation. Implement when Twilio integration is needed.
"""
import logging
from typing import List, Optional

from .base import BaseSMSProvider, SMSResult, BulkSMSResult, SMSStatus

logger = logging.getLogger(__name__)


class TwilioProvider(BaseSMSProvider):
    """
    Twilio SMS Provider implementation.

    TODO: Implement when Twilio integration is required.

    Required credentials:
        - account_sid: Twilio Account SID
        - auth_token: Twilio Auth Token
        - sender_id: Twilio Phone Number or Messaging Service SID
    """

    @property
    def provider_name(self) -> str:
        return 'twilio'

    def __init__(
        self,
        account_sid: Optional[str] = None,
        auth_token: Optional[str] = None,
        sender_id: Optional[str] = None
    ):
        """
        Initialize Twilio provider.

        Args:
            account_sid: Twilio Account SID
            auth_token: Twilio Auth Token
            sender_id: Default sender phone number
        """
        self.account_sid = account_sid or ''
        self.auth_token = auth_token or ''
        self.default_sender_id = sender_id or ''

        # Will be initialized when twilio package is installed
        self.client = None

    def _get_client(self):
        """Get or initialize Twilio client."""
        if self.client is None:
            try:
                from twilio.rest import Client
                self.client = Client(self.account_sid, self.auth_token)
            except ImportError:
                raise ImportError(
                    "twilio package is required for TwilioProvider. "
                    "Install it with: pip install twilio"
                )
        return self.client

    def send(
        self,
        phone: str,
        message: str,
        sender_id: Optional[str] = None
    ) -> SMSResult:
        """
        Send a single SMS via Twilio.

        TODO: Implement this method when Twilio integration is needed.
        """
        raise NotImplementedError(
            "TwilioProvider.send() is not yet implemented. "
            "Please implement when Twilio integration is required."
        )

    def send_bulk(
        self,
        recipients: List[str],
        message: str,
        sender_id: Optional[str] = None
    ) -> BulkSMSResult:
        """
        Send SMS to multiple recipients via Twilio.

        TODO: Implement this method when Twilio integration is needed.
        """
        raise NotImplementedError(
            "TwilioProvider.send_bulk() is not yet implemented. "
            "Please implement when Twilio integration is required."
        )

    def get_delivery_report(self, message_id: str) -> SMSResult:
        """
        Get delivery status for a sent message.

        TODO: Implement this method when Twilio integration is needed.
        """
        raise NotImplementedError(
            "TwilioProvider.get_delivery_report() is not yet implemented. "
            "Please implement when Twilio integration is required."
        )

    def get_balance(self) -> dict:
        """
        Get account balance from Twilio.

        TODO: Implement this method when Twilio integration is needed.
        """
        raise NotImplementedError(
            "TwilioProvider.get_balance() is not yet implemented. "
            "Please implement when Twilio integration is required."
        )
