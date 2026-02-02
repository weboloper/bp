# notifications/models/preference.py

from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from datetime import time

from notifications.constants import Channel


class NotificationPreference(models.Model):
    """
    User notification preferences.
    
    Global channel toggles + type-specific preferences.
    """
    
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notification_preference',
        verbose_name=_('User')
    )
    
    # ===== GLOBAL CHANNEL TOGGLES =====
    sms_enabled = models.BooleanField(_('SMS Enabled'), default=True)
    email_enabled = models.BooleanField(_('Email Enabled'), default=True)
    in_app_enabled = models.BooleanField(_('In-App Enabled'), default=True)
    push_enabled = models.BooleanField(_('Push Enabled'), default=True)
    
    # ===== TYPE-SPECIFIC PREFERENCES =====
    # Format: {"appointment_reminder": {"sms": true, "email": false}, ...}
    type_preferences = models.JSONField(
        _('Type Preferences'),
        default=dict,
        blank=True
    )
    
    # ===== QUIET HOURS =====
    quiet_hours_enabled = models.BooleanField(_('Quiet Hours Enabled'), default=False)
    quiet_hours_start = models.TimeField(_('Quiet Start'), default=time(22, 0))
    quiet_hours_end = models.TimeField(_('Quiet End'), default=time(8, 0))
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = _('Notification Preference')
        verbose_name_plural = _('Notification Preferences')
    
    def __str__(self):
        return f"{self.user.username} preferences"
    
    def is_channel_enabled(self, channel: str) -> bool:
        """Check if channel is globally enabled"""
        channel_map = {
            Channel.SMS: self.sms_enabled,
            Channel.EMAIL: self.email_enabled,
            Channel.IN_APP: self.in_app_enabled,
            Channel.PUSH: self.push_enabled,
        }
        return channel_map.get(channel, True)
    
    def is_type_enabled(self, notification_type: str, channel: str) -> bool:
        """Check if specific type+channel is enabled"""
        # First check global channel toggle
        if not self.is_channel_enabled(channel):
            return False
        
        # Then check type-specific
        type_prefs = self.type_preferences.get(notification_type, {})
        return type_prefs.get(channel, True)  # Default: enabled
    
    def is_quiet_hours(self) -> bool:
        """Check if current time is in quiet hours"""
        if not self.quiet_hours_enabled:
            return False
        
        from django.utils import timezone
        now = timezone.localtime().time()
        start = self.quiet_hours_start
        end = self.quiet_hours_end
        
        if start < end:
            return start <= now <= end
        else:
            # Overnight (e.g., 22:00 - 08:00)
            return now >= start or now <= end