# notifications/admin.py

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    Notification,
    NotificationTemplate,
    NotificationPreference,
    OutboundMessage,
)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'recipient', 'notification_type', 'title_short',
        'is_read',  'created_at'
    ]
    list_filter = ['is_read', 'notification_type', 'priority', 'created_at']
    search_fields = ['title', 'message', 'recipient__username', 'recipient__email']
    readonly_fields = ['created_at', 'updated_at', 'read_at']
    raw_id_fields = ['recipient',  'sender_user']
    date_hierarchy = 'created_at'

    fieldsets = (
        (None, {
            'fields': ('recipient', 'notification_type', 'title', 'message', 'priority')
        }),
        ('Sender', {
            'fields': ('sender_user',),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('is_read', 'read_at')
        }),
        ('Action', {
            'fields': ('action_url', 'action_label'),
            'classes': ('collapse',)
        }),
        ('Related Object', {
            'fields': ('content_type', 'object_id'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def title_short(self, obj):
        return obj.title[:50] + '...' if len(obj.title) > 50 else obj.title
    title_short.short_description = 'Title'


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = [
        'code', 'name', 'notification_type',
        'channels_display', 'is_active', 'updated_at'
    ]
    list_filter = ['is_active', 'notification_type', 'sms_enabled', 'email_enabled', 'in_app_enabled']
    search_fields = ['code', 'name', 'description']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        (None, {
            'fields': ('code', 'name', 'description', 'notification_type', 'is_active')
        }),
        ('SMS', {
            'fields': ('sms_enabled', 'sms_template'),
            'classes': ('collapse',)
        }),
        ('Email', {
            'fields': ('email_enabled', 'email_subject', 'email_body_text', 'email_body_html'),
            'classes': ('collapse',)
        }),
        ('In-App', {
            'fields': ('in_app_enabled', 'in_app_title', 'in_app_message'),
            'classes': ('collapse',)
        }),
        ('Push', {
            'fields': ('push_enabled', 'push_title', 'push_body'),
            'classes': ('collapse',)
        }),
        ('Settings', {
            'fields': ('default_priority', 'variables'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def channels_display(self, obj):
        channels = []
        if obj.sms_enabled:
            channels.append('SMS')
        if obj.email_enabled:
            channels.append('Email')
        if obj.in_app_enabled:
            channels.append('In-App')
        if obj.push_enabled:
            channels.append('Push')
        return ', '.join(channels) or '-'
    channels_display.short_description = 'Channels'


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'sms_enabled', 'email_enabled', 'in_app_enabled',
        'push_enabled', 'quiet_hours_enabled', 'updated_at'
    ]
    list_filter = ['sms_enabled', 'email_enabled', 'in_app_enabled', 'push_enabled', 'quiet_hours_enabled']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['user']

    fieldsets = (
        (None, {
            'fields': ('user',)
        }),
        ('Channel Toggles', {
            'fields': ('sms_enabled', 'email_enabled', 'in_app_enabled', 'push_enabled')
        }),
        ('Type Preferences', {
            'fields': ('type_preferences',),
            'classes': ('collapse',)
        }),
        ('Quiet Hours', {
            'fields': ('quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(OutboundMessage)
class OutboundMessageAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'channel', 'recipient_display', 'status_colored',
        'notification_type', 'provider_name', 'sent_at'
    ]
    list_filter = ['channel', 'status', 'notification_type', 'provider_name', 'created_at']
    search_fields = ['recipient_phone', 'recipient_email', 'recipient_name', 'subject', 'content']
    readonly_fields = [
        'created_at', 'updated_at', 'sent_at', 'delivered_at',
        'opened_at', 'clicked_at', 'provider_message_id', 'provider_response'
    ]
    raw_id_fields = ['sent_by',]
    date_hierarchy = 'created_at'

    fieldsets = (
        (None, {
            'fields': ('channel', 'status')
        }),
        ('Recipient', {
            'fields': ('recipient_phone', 'recipient_email', 'recipient_name')
        }),
        ('Content', {
            'fields': ('notification_type', 'subject', 'content', 'content_html')
        }),
        ('Provider', {
            'fields': ('provider_name', 'provider_message_id', 'provider_response'),
            'classes': ('collapse',)
        }),
        ('Credits & Tracking', {
            'fields': ('credits_used', 'open_count', 'click_count'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('scheduled_at', 'sent_at', 'delivered_at', 'opened_at', 'clicked_at', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
        ('Error & Retry', {
            'fields': ('error_message', 'retry_count', 'max_retries'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('sent_by', 'metadata'),
            'classes': ('collapse',)
        }),
    )

    def recipient_display(self, obj):
        if obj.channel == 'sms':
            return obj.recipient_phone
        return obj.recipient_email
    recipient_display.short_description = 'Recipient'

    def status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'sent': 'blue',
            'delivered': 'green',
            'failed': 'red',
            'rejected': 'darkred',
            'opened': 'green',
            'clicked': 'green',
            'bounced': 'red',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_colored.short_description = 'Status'