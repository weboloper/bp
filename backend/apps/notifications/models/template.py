# notifications/models/template.py

from django.db import models
from django.template import Template, Context
from django.utils.translation import gettext_lazy as _

from core.mixins import TimestampMixin
from notifications.constants import Channel, NotificationType, Priority


class NotificationTemplate(TimestampMixin, models.Model):
    """
    Multi-channel notification template.
    
    Bir notification_type için birden fazla kanal tanımlanabilir.
    """
    
    # ===== IDENTIFICATION =====
    code = models.CharField(
        _('Code'),
        max_length=50,
        db_index=True,
        help_text=_('Unique identifier, e.g., appointment_reminder')
    )
    name = models.CharField(_('Name'), max_length=100)
    description = models.TextField(_('Description'), blank=True)
    
    notification_type = models.CharField(
        _('Notification Type'),
        max_length=50,
        choices=NotificationType.choices
    )
    
    # ===== CHANNEL SETTINGS =====
    # Her kanal için ayrı enable/template
    
    # SMS
    sms_enabled = models.BooleanField(_('SMS Enabled'), default=False)
    sms_template = models.TextField(
        _('SMS Template'),
        blank=True,
        help_text=_('Use {{ variable }} for placeholders. Max 160 chars.')
    )
    
    # Email
    email_enabled = models.BooleanField(_('Email Enabled'), default=False)
    email_subject = models.CharField(_('Email Subject'), max_length=255, blank=True)
    email_body_text = models.TextField(_('Email Body (Text)'), blank=True)
    email_body_html = models.TextField(_('Email Body (HTML)'), blank=True)
    
    # In-App
    in_app_enabled = models.BooleanField(_('In-App Enabled'), default=False)
    in_app_title = models.CharField(_('In-App Title'), max_length=255, blank=True)
    in_app_message = models.TextField(_('In-App Message'), blank=True)
    
    # Push (future)
    push_enabled = models.BooleanField(_('Push Enabled'), default=False)
    push_title = models.CharField(_('Push Title'), max_length=100, blank=True)
    push_body = models.CharField(_('Push Body'), max_length=255, blank=True)
    
    # ===== SETTINGS =====
    default_priority = models.CharField(
        _('Default Priority'),
        max_length=10,
        choices=Priority.choices,
        default=Priority.NORMAL
    )
    
    # Available variables for documentation
    variables = models.JSONField(
        _('Variables'),
        default=dict,
        blank=True,
        help_text=_('{"client_name": "Client full name", "date": "Appointment date"}')
    )
    
    is_active = models.BooleanField(_('Is Active'), default=True)
    
    class Meta:
        verbose_name = _('Notification Template')
        verbose_name_plural = _('Notification Templates')
        ordering = ['code']
        constraints = [
            models.UniqueConstraint(fields=['code'], name='unique_template_code')
        ]

    def __str__(self):
        return self.name
    
    def get_enabled_channels(self) -> list:
        """Return list of enabled channels"""
        channels = []
        if self.sms_enabled:
            channels.append(Channel.SMS)
        if self.email_enabled:
            channels.append(Channel.EMAIL)
        if self.in_app_enabled:
            channels.append(Channel.IN_APP)
        if self.push_enabled:
            channels.append(Channel.PUSH)
        return channels
    
    def render(self, channel: str, context: dict) -> dict:
        """
        Render template for specific channel
        
        Returns dict with rendered content
        """
        def _render(template_str: str) -> str:
            if not template_str:
                return ''
            return Template(template_str).render(Context(context))
        
        if channel == Channel.SMS and self.sms_enabled:
            return {
                'content': _render(self.sms_template)
            }
        
        elif channel == Channel.EMAIL and self.email_enabled:
            return {
                'subject': _render(self.email_subject),
                'body_text': _render(self.email_body_text),
                'body_html': _render(self.email_body_html)
            }
        
        elif channel == Channel.IN_APP and self.in_app_enabled:
            return {
                'title': _render(self.in_app_title),
                'message': _render(self.in_app_message)
            }
        
        elif channel == Channel.PUSH and self.push_enabled:
            return {
                'title': _render(self.push_title),
                'body': _render(self.push_body)
            }
        
        return {}