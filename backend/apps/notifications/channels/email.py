# notifications/channels/email.py

import logging
from typing import Dict, Any
from django.utils import timezone

from providers.email import get_email_provider
from notifications.models import OutboundMessage
from notifications.constants import Channel, DeliveryStatus
from .base import BaseChannel

logger = logging.getLogger(__name__)


class EmailChannel(BaseChannel):
    """Email delivery channel"""
    
    @property
    def channel_name(self) -> str:
        return Channel.EMAIL
    
    def send(
        self,
        recipient: str,  # Email address
        content: Dict[str, str],
        sent_by=None,
        notification_type: str = '',
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send Email

        Args:
            recipient: Email address
            content: {"subject": "", "body_text": "", "body_html": ""}
            sent_by: User

        Returns:
            {"success": bool, "message_id": str, "outbound_id": int, ...}
        """
        provider = get_email_provider()

        subject = content.get('subject', '')
        body_text = content.get('body_text', '')
        body_html = content.get('body_html', '')

        if not subject or (not body_text and not body_html):
            return {'success': False, 'error': 'Empty subject or body'}

        # Validate email
        if not provider.validate_email(recipient):
            return {'success': False, 'error': 'Invalid email address'}

        # Get from settings
        from_email = kwargs.get('from_email') or getattr(provider, 'default_from', None)
        from_name = kwargs.get('from_name')

        # Create outbound record
        outbound = OutboundMessage.objects.create(
            channel=Channel.EMAIL,
            recipient_email=recipient,
            recipient_name=kwargs.get('recipient_name', ''),
            notification_type=notification_type,
            subject=subject,
            content=body_text,
            content_html=body_html,
            status=DeliveryStatus.PENDING,
            sent_by=sent_by,
            metadata=kwargs.get('metadata', {})
        )
        
        # Send via provider
        try:
            result = provider.send(
                to_email=recipient,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                from_email=from_email,
                from_name=from_name
            )
            
            outbound.provider_name = provider.provider_name
            outbound.provider_message_id = result.message_id or ''
            outbound.provider_response = result.raw_response
            
            if result.success:
                outbound.status = DeliveryStatus.SENT
                outbound.sent_at = timezone.now()
                logger.info(f"Email sent: {outbound.id} → {recipient}")
            else:
                outbound.status = DeliveryStatus.FAILED
                outbound.error_message = result.error_message or ''
                logger.error(f"Email failed: {outbound.id} - {result.error_message}")
            
            outbound.save()
            
            return {
                'success': result.success,
                'outbound_id': outbound.id,
                'message_id': result.message_id,
                'error': result.error_message if not result.success else None
            }
            
        except Exception as e:
            outbound.status = DeliveryStatus.FAILED
            outbound.error_message = str(e)
            outbound.save()
            logger.exception(f"Email exception: {outbound.id}")
            return {'success': False, 'outbound_id': outbound.id, 'error': str(e)}
    
    def validate_recipient(self, recipient: str) -> bool:
        provider = get_email_provider()
        return provider.validate_email(recipient)