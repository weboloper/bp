# notifications/models/outbound.py

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

from core.mixins import  TimestampMixin
from notifications.constants import Channel, NotificationType, DeliveryStatus


class OutboundMessage(TimestampMixin, models.Model):
    """
    Giden mesaj kayıtları - SMS ve Email için tek tablo.
    
    """
    
    # ===== CHANNEL =====
    channel = models.CharField(
        _('Channel'),
        max_length=20,
        choices=Channel.choices,
        db_index=True
    )
    
    # ===== RECIPIENT =====
    # SMS için phone, Email için email kullanılır
    recipient_phone = models.CharField(_('Phone'), max_length=20, blank=True)
    recipient_email = models.EmailField(_('Email'), blank=True)
    recipient_name = models.CharField(_('Name'), max_length=200, blank=True)
    
    # İlişkili Client (opsiyonel)
    # client = models.ForeignKey(
    #     'clients.Client',
    #     on_delete=models.SET_NULL,
    #     null=True,
    #     blank=True,
    #     related_name='outbound_messages',
    #     verbose_name=_('Client')
    # )
    
    # ===== CONTENT =====
    notification_type = models.CharField(
        _('Notification Type'),
        max_length=50,
        choices=NotificationType.choices,
        blank=True
    )
    
    # SMS: sadece content kullanılır
    # Email: subject + content (text) + content_html
    subject = models.CharField(_('Subject'), max_length=255, blank=True)
    content = models.TextField(_('Content'))
    content_html = models.TextField(_('HTML Content'), blank=True)
    
    # ===== STATUS =====
    status = models.CharField(
        _('Status'),
        max_length=20,
        choices=DeliveryStatus.choices,
        default=DeliveryStatus.PENDING,
        db_index=True
    )
    
    # ===== PROVIDER INFO =====
    provider_name = models.CharField(_('Provider'), max_length=50, blank=True)
    provider_message_id = models.CharField(
        _('Provider Message ID'),
        max_length=255,
        blank=True,
        db_index=True
    )
    provider_response = models.JSONField(_('Provider Response'), null=True, blank=True)
    
    # ===== CREDITS (SMS only) =====
    credits_used = models.PositiveIntegerField(_('Credits Used'), default=0)
    
    # ===== TIMESTAMPS =====
    scheduled_at = models.DateTimeField(_('Scheduled At'), null=True, blank=True)
    sent_at = models.DateTimeField(_('Sent At'), null=True, blank=True)
    delivered_at = models.DateTimeField(_('Delivered At'), null=True, blank=True)
    opened_at = models.DateTimeField(_('Opened At'), null=True, blank=True)  # Email
    clicked_at = models.DateTimeField(_('Clicked At'), null=True, blank=True)  # Email
    
    # ===== TRACKING (Email) =====
    open_count = models.PositiveIntegerField(_('Open Count'), default=0)
    click_count = models.PositiveIntegerField(_('Click Count'), default=0)
    
    # ===== ERROR =====
    error_message = models.TextField(_('Error Message'), blank=True)
    retry_count = models.PositiveIntegerField(_('Retry Count'), default=0)
    max_retries = models.PositiveIntegerField(_('Max Retries'), default=3)
    
    # ===== SENDER =====
    sent_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_messages',
        verbose_name=_('Sent By')
    )
    
    # ===== METADATA =====
    metadata = models.JSONField(_('Metadata'), default=dict, blank=True)
    
    class Meta:
        verbose_name = _('Outbound Message')
        verbose_name_plural = _('Outbound Messages')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['channel', 'status', '-created_at']),
            models.Index(fields=['recipient_phone', '-created_at']),
            models.Index(fields=['recipient_email', '-created_at']),
        ]
    
    def __str__(self):
        recipient = self.recipient_phone or self.recipient_email
        return f"{self.channel.upper()} → {recipient} ({self.status})"
    
    @property
    def can_retry(self) -> bool:
        return self.status == DeliveryStatus.FAILED and self.retry_count < self.max_retries
    
    @property
    def recipient(self) -> str:
        """Return appropriate recipient based on channel"""
        if self.channel == Channel.SMS:
            return self.recipient_phone
        elif self.channel == Channel.EMAIL:
            return self.recipient_email
        return ''