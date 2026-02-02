# notifications/channels/in_app.py

import logging
from typing import Dict, Any
from django.contrib.contenttypes.models import ContentType

from notifications.models import Notification, NotificationPreference
from notifications.constants import Channel, Priority
from .base import BaseChannel

logger = logging.getLogger(__name__)


class InAppChannel(BaseChannel):
    """In-App notification channel"""
    
    @property
    def channel_name(self) -> str:
        return Channel.IN_APP
    
    def send(
        self,
        recipient,  # User instance
        content: Dict[str, str],
        sender_user=None,
        notification_type: str = '',
        priority: str = Priority.NORMAL,
        action_url: str = '',
        action_label: str = '',
        related_object=None,
        is_system: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create in-app notification

        Args:
            recipient: User instance
            content: {"title": "", "message": ""}
            sender_user: User who triggered
            notification_type: Type identifier
            priority: Priority level
            action_url: CTA URL
            action_label: CTA label
            related_object: Related model instance
            is_system: Whether this is a system notification

        Returns:
            {"success": bool, "notification_id": int, ...}
        """
        title = content.get('title', '')
        message = content.get('message', '')

        if not title or not message:
            return {'success': False, 'error': 'Empty title or message'}

        # Check user preference
        try:
            pref = recipient.notification_preference
            if not pref.is_type_enabled(notification_type, Channel.IN_APP):
                logger.debug(f"In-app disabled for {recipient}: {notification_type}")
                return {'success': False, 'error': 'Disabled by user preference'}
        except NotificationPreference.DoesNotExist:
            pass  # No preferences, allow

        # Related object content type
        content_type = None
        object_id = None
        if related_object:
            content_type = ContentType.objects.get_for_model(related_object)
            object_id = related_object.pk

        # Create notification
        try:
            notification = Notification.objects.create(
                recipient=recipient,
                is_system=is_system,
                sender_user=sender_user,
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                action_url=action_url,
                action_label=action_label,
                content_type=content_type,
                object_id=object_id,
                metadata=kwargs.get('metadata', {})
            )

            logger.info(f"In-app notification created: {notification.id} → {recipient}")

            return {
                'success': True,
                'notification_id': notification.id
            }

        except Exception as e:
            logger.exception(f"In-app notification failed for {recipient}")
            return {'success': False, 'error': str(e)}