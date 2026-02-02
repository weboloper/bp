# notifications/channels/sms.py

import logging
from typing import Dict, Any
from django.utils import timezone

from providers.sms import get_sms_provider
from notifications.models import OutboundMessage
from notifications.constants import Channel, DeliveryStatus
from .base import BaseChannel

logger = logging.getLogger(__name__)


class SMSChannel(BaseChannel):
    """SMS delivery channel"""

    @property
    def channel_name(self) -> str:
        return Channel.SMS

    def send(
        self,
        recipient: str,  # Phone number
        content: Dict[str, str],
        sent_by=None,
        notification_type: str = '',
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send SMS

        Args:
            recipient: Phone number
            content: {"content": "Message text"}
            sent_by: User
            notification_type: For logging

        Returns:
            {"success": bool, "message_id": str, "outbound_id": int, ...}
        """
        provider = get_sms_provider()
        message_text = content.get('content', '')

        if not message_text:
            return {'success': False, 'error': 'Empty message'}

        # Validate phone
        if not provider.validate_phone(recipient):
            return {'success': False, 'error': 'Invalid phone number'}

        # Calculate credits
        credits_needed = provider.calculate_credits(message_text)

        # Create outbound record
        outbound = OutboundMessage.objects.create(
            channel=Channel.SMS,
            recipient_phone=provider.normalize_phone(recipient),
            recipient_name=kwargs.get('recipient_name', ''),
            notification_type=notification_type,
            content=message_text,
            status=DeliveryStatus.PENDING,
            credits_used=credits_needed,
            sent_by=sent_by,
            metadata=kwargs.get('metadata', {})
        )

        # Send via provider
        try:
            result = provider.send(recipient, message_text)

            outbound.provider_name = provider.provider_name
            outbound.provider_message_id = result.message_id or ''
            outbound.provider_response = result.raw_response

            if result.success:
                outbound.status = DeliveryStatus.SENT
                outbound.sent_at = timezone.now()
                logger.info(f"SMS sent: {outbound.id} → {recipient}")
            else:
                outbound.status = DeliveryStatus.FAILED
                outbound.error_message = result.error_message or ''
                logger.error(f"SMS failed: {outbound.id} - {result.error_message}")

            outbound.save()

            return {
                'success': result.success,
                'outbound_id': outbound.id,
                'message_id': result.message_id,
                'credits_used': credits_needed if result.success else 0,
                'error': result.error_message if not result.success else None
            }

        except Exception as e:
            outbound.status = DeliveryStatus.FAILED
            outbound.error_message = str(e)
            outbound.save()
            logger.exception(f"SMS exception: {outbound.id}")
            return {'success': False, 'outbound_id': outbound.id, 'error': str(e)}
    
    def validate_recipient(self, recipient: str) -> bool:
        provider = get_sms_provider()
        return provider.validate_phone(recipient)