# notifications/api/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model

from notifications.models import (
    Notification,
    NotificationTemplate,
    NotificationPreference,
    OutboundMessage,
)
from notifications.constants import Channel, NotificationType

User = get_user_model()


# ==================== NOTIFICATION ====================

class NotificationSerializer(serializers.ModelSerializer):
    """Full notification detail"""
    sender_display = serializers.CharField(source='get_sender_display', read_only=True)

    class Meta:
        model = Notification
        fields = [
            'id', 'notification_type', 'title', 'message',
            'priority', 'is_read', 'read_at',
            'is_system', 'sender_display',
            'action_url', 'action_label',
            'metadata', 'created_at'
        ]
        read_only_fields = fields


class NotificationListSerializer(serializers.ModelSerializer):
    """Lightweight for listing"""
    sender_display = serializers.CharField(source='get_sender_display', read_only=True)

    class Meta:
        model = Notification
        fields = [
            'id', 'notification_type', 'title',
            'priority', 'is_read', 'sender_display',
            'action_url', 'created_at'
        ]
        read_only_fields = fields


class MarkReadSerializer(serializers.Serializer):
    """Mark notifications as read"""
    notification_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="List of notification IDs. If empty, marks all as read."
    )


# ==================== OUTBOUND MESSAGE ====================

class OutboundMessageSerializer(serializers.ModelSerializer):
    """Full outbound message detail"""
    recipient = serializers.CharField(read_only=True)

    class Meta:
        model = OutboundMessage
        fields = [
            'id', 'channel', 'recipient', 'recipient_phone', 'recipient_email',
            'recipient_name', 'notification_type',
            'subject', 'content', 'content_html',
            'status', 'provider_name', 'provider_message_id',
            'credits_used', 'error_message',
            'scheduled_at', 'sent_at', 'delivered_at',
            'open_count', 'click_count',
            'created_at'
        ]
        read_only_fields = fields


class OutboundMessageListSerializer(serializers.ModelSerializer):
    """Lightweight for listing"""
    recipient = serializers.CharField(read_only=True)

    class Meta:
        model = OutboundMessage
        fields = [
            'id', 'channel', 'recipient', 'recipient_name',
            'notification_type', 'status', 'credits_used',
            'sent_at', 'created_at'
        ]
        read_only_fields = fields


# ==================== TEMPLATE ====================

class NotificationTemplateSerializer(serializers.ModelSerializer):
    """Full template CRUD"""
    enabled_channels = serializers.ListField(
        source='get_enabled_channels',
        read_only=True
    )

    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'code', 'name', 'description', 'notification_type',
            'sms_enabled', 'sms_template',
            'email_enabled', 'email_subject', 'email_body_text', 'email_body_html',
            'in_app_enabled', 'in_app_title', 'in_app_message',
            'push_enabled', 'push_title', 'push_body',
            'default_priority', 'variables', 'is_active',
            'enabled_channels', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'enabled_channels', 'created_at', 'updated_at']


class NotificationTemplateListSerializer(serializers.ModelSerializer):
    """Lightweight for listing"""
    enabled_channels = serializers.ListField(
        source='get_enabled_channels',
        read_only=True
    )

    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'code', 'name', 'notification_type',
            'enabled_channels', 'is_active', 'updated_at'
        ]
        read_only_fields = fields


# ==================== PREFERENCE ====================

class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """User notification preferences"""

    class Meta:
        model = NotificationPreference
        fields = [
            'sms_enabled', 'email_enabled', 'in_app_enabled', 'push_enabled',
            'type_preferences',
            'quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end',
            'updated_at'
        ]
        read_only_fields = ['updated_at']


# ==================== SEND NOTIFICATION ====================

class SendNotificationSerializer(serializers.Serializer):
    """Input for sending notifications via notify()"""

    code = serializers.CharField(
        max_length=50,
        help_text="Template code, e.g., 'appointment_reminder'"
    )
    recipient_type = serializers.ChoiceField(
        choices=['client', 'user'],
        help_text="Type of recipient"
    )
    recipient_id = serializers.IntegerField(
        help_text="ID of the recipient (Client or User)"
    )
    context = serializers.DictField(
        child=serializers.CharField(),
        required=False,
        default=dict,
        help_text="Template variables"
    )
    channels = serializers.ListField(
        child=serializers.ChoiceField(choices=Channel.choices),
        required=False,
        help_text="Override channels (uses template default if not provided)"
    )

    def validate(self, data):
        recipient_type = data.get('recipient_type')
        recipient_id = data.get('recipient_id')

        if recipient_type == 'client':
            from clients.models import Client
            try:
                data['recipient'] = Client.objects.get(id=recipient_id)
            except Client.DoesNotExist:
                raise serializers.ValidationError({'recipient_id': 'Client not found'})
        else:
            try:
                data['recipient'] = User.objects.get(id=recipient_id)
            except User.DoesNotExist:
                raise serializers.ValidationError({'recipient_id': 'User not found'})

        return data


class SendDirectSMSSerializer(serializers.Serializer):
    """Direct SMS sending (without template)"""

    phone = serializers.CharField(max_length=20)
    message = serializers.CharField(max_length=918)  # 6 SMS max

    def validate_phone(self, value):
        from providers.sms import get_sms_provider
        provider = get_sms_provider()
        if not provider.validate_phone(value):
            raise serializers.ValidationError('Invalid phone number')
        return value


class SendDirectEmailSerializer(serializers.Serializer):
    """Direct email sending (without template)"""

    email = serializers.EmailField()
    subject = serializers.CharField(max_length=255)
    body_text = serializers.CharField()
    body_html = serializers.CharField(required=False, allow_blank=True)


# ==================== SMS UTILITIES ====================

class SMSBalanceSerializer(serializers.Serializer):
    """SMS balance response"""
    provider_balance = serializers.DictField(read_only=True)


class SMSCalculateSerializer(serializers.Serializer):
    """Calculate SMS credits needed"""
    message = serializers.CharField(
        help_text="Message text to calculate credits for"
    )


class SMSCalculateResponseSerializer(serializers.Serializer):
    """SMS calculation response"""
    message_length = serializers.IntegerField()
    credits_needed = serializers.IntegerField()
    encoding = serializers.CharField()  # GSM7 or UCS2
    has_turkish_chars = serializers.BooleanField()
