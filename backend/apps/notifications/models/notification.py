# notifications/models/notification.py

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

from core.mixins import TimestampMixin
from notifications.constants import NotificationType, Priority


class Notification(TimestampMixin, models.Model):
    """
    In-App Notification - UI'da görünen bildirimler
    
    Sadece User'lara gönderilir (Client değil).
    Client'lara SMS/Email gönderilir.
    """
    
    # ===== RECIPIENT =====
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications',
        verbose_name=_('Recipient')
    )
    
    # ===== SENDER INFO =====
    is_system = models.BooleanField(
        _('System Notification'),
        default=False,
        help_text=_('True if sent by platform')
    )
    sender_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications_sent',
        verbose_name=_('Sender User')
    )
    
    # ===== CONTENT =====
    notification_type = models.CharField(
        _('Type'),
        max_length=50,
        choices=NotificationType.choices,
        db_index=True
    )
    title = models.CharField(_('Title'), max_length=255)
    message = models.TextField(_('Message'))
    
    # ===== PRIORITY & STATUS =====
    priority = models.CharField(
        _('Priority'),
        max_length=10,
        choices=Priority.choices,
        default=Priority.NORMAL
    )
    is_read = models.BooleanField(_('Is Read'), default=False, db_index=True)
    read_at = models.DateTimeField(_('Read At'), null=True, blank=True)
    
    # ===== ACTION (Optional CTA) =====
    action_url = models.CharField(_('Action URL'), max_length=500, blank=True)
    action_label = models.CharField(_('Action Label'), max_length=50, blank=True)
    
    # ===== RELATED OBJECT (Generic FK) =====
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')
    
    # ===== METADATA =====
    metadata = models.JSONField(_('Metadata'), default=dict, blank=True)
    
    class Meta:
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', 'is_read', '-created_at']),
            models.Index(fields=['recipient', 'notification_type']),
        ]
    
    def __str__(self):
        return f"{self.notification_type}: {self.title[:50]}"
    
    def mark_as_read(self):
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at', 'updated_at'])
    
    def get_sender_display(self) -> str:
        if self.is_system:
            return _("System")
        if self.sender_user:
            return self.sender_user.get_full_name() or self.sender_user.username
        return _("Unknown")