# notifications/api/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'notifications'

router = DefaultRouter()
router.register(r'notifications', views.NotificationViewSet, basename='notification')
router.register(r'outbound', views.OutboundMessageViewSet, basename='outbound')
router.register(r'templates', views.NotificationTemplateViewSet, basename='template')

urlpatterns = [
    path('', include(router.urls)),
    path('preferences/', views.PreferenceView.as_view(), name='preferences'),
    path('send/', views.SendNotificationView.as_view(), name='send'),
    path('send/sms/', views.SendDirectSMSView.as_view(), name='send-sms'),
    path('send/email/', views.SendDirectEmailView.as_view(), name='send-email'),
    path('sms/balance/', views.SMSBalanceView.as_view(), name='sms-balance'),
    path('sms/calculate/', views.SMSCalculateView.as_view(), name='sms-calculate'),
]
