# notifications/api/views.py

from rest_framework import viewsets, views, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone

from notifications.models import (
    Notification,
    NotificationTemplate,
    NotificationPreference,
    OutboundMessage,
)
from notifications.services import notify, NotificationDispatcher
from notifications.constants import Channel

from .serializers import (
    NotificationSerializer,
    NotificationListSerializer,
    MarkReadSerializer,
    OutboundMessageSerializer,
    OutboundMessageListSerializer,
    NotificationTemplateSerializer,
    NotificationTemplateListSerializer,
    NotificationPreferenceSerializer,
    SendNotificationSerializer,
    SendDirectSMSSerializer,
    SendDirectEmailSerializer,
    SMSBalanceSerializer,
    SMSCalculateSerializer,
    SMSCalculateResponseSerializer,
)


# ==================== NOTIFICATION ====================

class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    User's in-app notifications

    list: Get all notifications for current user
    retrieve: Get notification detail
    mark_read: Mark notifications as read
    unread_count: Get count of unread notifications
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.filter(
            recipient=self.request.user
        ).select_related('sender_user')

    def get_serializer_class(self):
        if self.action == 'list':
            return NotificationListSerializer
        return NotificationSerializer

    @action(detail=False, methods=['post'])
    def mark_read(self, request):
        """Mark notifications as read"""
        serializer = MarkReadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        notification_ids = serializer.validated_data.get('notification_ids', [])

        qs = self.get_queryset().filter(is_read=False)
        if notification_ids:
            qs = qs.filter(id__in=notification_ids)

        count = qs.update(is_read=True, read_at=timezone.now())

        return Response({'marked_count': count})

    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        """Get unread notification count"""
        count = self.get_queryset().filter(is_read=False).count()
        return Response({'unread_count': count})

    @action(detail=True, methods=['post'])
    def read(self, request, pk=None):
        """Mark single notification as read"""
        notification = self.get_object()
        notification.mark_as_read()
        return Response({'success': True})


# ==================== OUTBOUND MESSAGE ====================

class OutboundMessageViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Outbound message history (SMS/Email)

    list: Get all outbound messages
    retrieve: Get message detail
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = OutboundMessageSerializer

    def get_queryset(self):
        qs = OutboundMessage.objects.all()

        # Apply filters
        channel = self.request.query_params.get('channel')
        status_filter = self.request.query_params.get('status')

        if channel:
            qs = qs.filter(channel=channel)
        if status_filter:
            qs = qs.filter(status=status_filter)

        return qs.select_related('sent_by').order_by('-created_at')

    def get_serializer_class(self):
        if self.action == 'list':
            return OutboundMessageListSerializer
        return OutboundMessageSerializer


# ==================== TEMPLATE ====================

class NotificationTemplateViewSet(viewsets.ModelViewSet):
    """
    Notification templates CRUD
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationTemplateSerializer
    queryset = NotificationTemplate.objects.all().order_by('code')

    def get_serializer_class(self):
        if self.action == 'list':
            return NotificationTemplateListSerializer
        return NotificationTemplateSerializer


# ==================== PREFERENCE ====================

class PreferenceView(views.APIView):
    """
    User notification preferences

    GET: Get current preferences
    PUT/PATCH: Update preferences
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        pref, _ = NotificationPreference.objects.get_or_create(
            user=request.user
        )
        serializer = NotificationPreferenceSerializer(pref)
        return Response(serializer.data)

    def put(self, request):
        pref, _ = NotificationPreference.objects.get_or_create(
            user=request.user
        )
        serializer = NotificationPreferenceSerializer(pref, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def patch(self, request):
        pref, _ = NotificationPreference.objects.get_or_create(
            user=request.user
        )
        serializer = NotificationPreferenceSerializer(
            pref, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# ==================== SEND NOTIFICATION ====================

class SendNotificationView(views.APIView):
    """
    Send notification using template

    POST: Send notification via notify()
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SendNotificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = notify(
            code=serializer.validated_data['code'],
            recipient=serializer.validated_data['recipient'],
            context=serializer.validated_data.get('context', {}),
            channels=serializer.validated_data.get('channels'),
            sent_by=request.user
        )

        return Response(result)


class SendDirectSMSView(views.APIView):
    """Send SMS directly without template"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SendDirectSMSSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from notifications.channels import get_channel

        channel = get_channel(Channel.SMS)
        result = channel.send(
            recipient=serializer.validated_data['phone'],
            content={'content': serializer.validated_data['message']},
            sent_by=request.user,
            notification_type='custom'
        )

        return Response(result)


class SendDirectEmailView(views.APIView):
    """Send email directly without template"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SendDirectEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from notifications.channels import get_channel

        channel = get_channel(Channel.EMAIL)
        result = channel.send(
            recipient=serializer.validated_data['email'],
            content={
                'subject': serializer.validated_data['subject'],
                'body_text': serializer.validated_data['body_text'],
                'body_html': serializer.validated_data.get('body_html', ''),
            },
            sent_by=request.user,
            notification_type='custom'
        )

        return Response(result)


# ==================== SMS UTILITIES ====================

class SMSBalanceView(views.APIView):
    """Get SMS balance"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from providers.sms import get_sms_provider

        # Provider balance
        try:
            provider = get_sms_provider()
            provider_balance = provider.get_balance()
        except Exception:
            provider_balance = {'error': 'Could not fetch provider balance'}

        return Response({
            'provider_balance': provider_balance
        })


class SMSCalculateView(views.APIView):
    """Calculate SMS credits for a message"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = SMSCalculateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        message = serializer.validated_data['message']

        from providers.sms import get_sms_provider

        provider = get_sms_provider()
        credits = provider.calculate_credits(message)

        # Check for Turkish characters
        turkish_chars = set('çÇğĞıİöÖşŞüÜ')
        has_turkish = bool(turkish_chars.intersection(set(message)))

        return Response({
            'message_length': len(message),
            'credits_needed': credits,
            'encoding': 'UCS2' if has_turkish else 'GSM7',
            'has_turkish_chars': has_turkish
        })
