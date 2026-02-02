# notifications/signals.py
"""
Notification signal handlers.

Bu dosya, uygulama genelinde otomatik bildirim gönderimini sağlar.
Model signal'ları ile notification dispatcher'ı entegre eder.

Kullanım:
    1. Signal handler'ı tanımla
    2. apps.py'de ready() metodunda import et

Not: Aşağıdaki örnekler yorum satırı olarak verilmiştir.
     İhtiyaca göre aktifleştirin.
"""

import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)


# =============================================================================
# APPOINTMENT SIGNALS (Örnek)
# =============================================================================

# @receiver(post_save, sender='appointments.Appointment')
# def notify_staff_on_new_appointment(sender, instance, created, **kwargs):
#     """
#     Yeni randevu oluşturulduğunda ilgili staff'a bildirim gönder.
#     """
#     if not created:
#         return
#
#     from notifications.services import NotificationDispatcher
#     from notifications.constants import NotificationType
#
#     # Staff'a in-app bildirim
#     if instance.staff and instance.staff.user:
#         NotificationDispatcher.notify_user(
#             user=instance.staff.user,
#             notification_type=NotificationType.APPOINTMENT_NEW,
#             title="Yeni Randevu",
#             message=f"{instance.client.full_name} - {instance.start_time.strftime('%d.%m.%Y %H:%M')}",
#             tenant=instance.company,
#             related_object=instance,
#             action_url=f"/appointments/{instance.id}",
#             action_label="Görüntüle"
#         )
#
#     logger.info(f"New appointment notification sent for appointment {instance.id}")


# @receiver(post_save, sender='appointments.Appointment')
# def notify_client_on_appointment_confirmation(sender, instance, created, **kwargs):
#     """
#     Randevu oluşturulduğunda müşteriye SMS/Email gönder.
#     """
#     if not created:
#         return
#
#     from notifications.services import notify
#
#     # Template-based SMS/Email
#     notify(
#         code='appointment_confirmation',
#         tenant=instance.company,
#         recipient=instance.client,
#         context={
#             'client_name': instance.client.first_name,
#             'service_name': instance.service.name if instance.service else '',
#             'date': instance.start_time.strftime('%d.%m.%Y'),
#             'time': instance.start_time.strftime('%H:%M'),
#             'staff_name': instance.staff.full_name if instance.staff else '',
#             'company_name': instance.company.name,
#             'company_phone': instance.company.phone or '',
#         }
#     )
#
#     logger.info(f"Appointment confirmation sent to client {instance.client.id}")


# =============================================================================
# APPOINTMENT CANCELLATION
# =============================================================================

# @receiver(post_delete, sender='appointments.Appointment')
# def notify_on_appointment_cancelled(sender, instance, **kwargs):
#     """
#     Randevu iptal edildiğinde bildirim gönder.
#     """
#     from notifications.services import notify, NotificationDispatcher
#     from notifications.constants import NotificationType
#
#     # Staff'a in-app bildirim
#     if instance.staff and instance.staff.user:
#         NotificationDispatcher.notify_user(
#             user=instance.staff.user,
#             notification_type=NotificationType.APPOINTMENT_CANCELLED,
#             title="Randevu İptal Edildi",
#             message=f"{instance.client.full_name} - {instance.start_time.strftime('%d.%m.%Y %H:%M')}",
#             tenant=instance.company
#         )
#
#     # Müşteriye SMS/Email
#     notify(
#         code='appointment_cancelled_client',
#         tenant=instance.company,
#         recipient=instance.client,
#         context={
#             'client_name': instance.client.first_name,
#             'date': instance.start_time.strftime('%d.%m.%Y'),
#             'time': instance.start_time.strftime('%H:%M'),
#             'company_name': instance.company.name,
#             'company_phone': instance.company.phone or '',
#         }
#     )


# =============================================================================
# CLIENT SIGNALS
# =============================================================================

# @receiver(post_save, sender='clients.Client')
# def notify_staff_on_new_client(sender, instance, created, **kwargs):
#     """
#     Yeni müşteri eklendiğinde tüm tenant staff'ına bildirim.
#     """
#     if not created:
#         return
#
#     from notifications.services import NotificationDispatcher
#     from notifications.constants import NotificationType
#
#     NotificationDispatcher.notify_tenant_users(
#         tenant=instance.company,
#         notification_type=NotificationType.CLIENT_NEW,
#         title="Yeni Müşteri",
#         message=f"{instance.full_name} sisteme eklendi.",
#         action_url=f"/clients/{instance.id}",
#         action_label="Profili Gör"
#     )


# =============================================================================
# BILLING SIGNALS
# =============================================================================

# @receiver(post_save, sender='billing.SmsTransaction')
# def check_sms_credits_low(sender, instance, **kwargs):
#     """
#     SMS kredisi azaldığında uyarı gönder.
#     """
#     from billing.services import SmsService
#     from notifications.services import NotificationDispatcher
#     from notifications.constants import NotificationType
#
#     balance = SmsService.get_balance(instance.tenant)
#
#     # Düşük kredi uyarısı (örn: 50'nin altında)
#     if balance < 50 and balance > 0:
#         # Tenant admin'lerine bildirim
#         from tenants.models import CompanyMembership
#         admins = CompanyMembership.objects.filter(
#             company=instance.tenant,
#             role='admin',
#             is_active=True
#         ).select_related('user')
#
#         for membership in admins:
#             NotificationDispatcher.notify_user(
#                 user=membership.user,
#                 notification_type=NotificationType.SMS_CREDIT_LOW,
#                 title="SMS Kredisi Azalıyor",
#                 message=f"Kalan kredi: {balance}. Lütfen kredi yükleyin.",
#                 tenant=instance.tenant,
#                 action_url="/billing/sms",
#                 action_label="Kredi Yükle"
#             )


# =============================================================================
# SYSTEM ANNOUNCEMENTS (Admin tarafından tetiklenir)
# =============================================================================

# def send_system_announcement(title: str, message: str, user_ids: list = None):
#     """
#     Sistem duyurusu gönder.
#
#     Args:
#         title: Duyuru başlığı
#         message: Duyuru içeriği
#         user_ids: Belirli kullanıcılara gönder (None = herkese)
#     """
#     from django.contrib.auth import get_user_model
#     from notifications.services import NotificationDispatcher
#     from notifications.constants import NotificationType
#
#     User = get_user_model()
#
#     if user_ids:
#         users = User.objects.filter(id__in=user_ids, is_active=True)
#     else:
#         users = User.objects.filter(is_active=True)
#
#     for user in users:
#         NotificationDispatcher.system_notify_user(
#             user=user,
#             notification_type=NotificationType.SYSTEM_ANNOUNCEMENT,
#             title=title,
#             message=message
#         )
#
#     logger.info(f"System announcement sent to {users.count()} users")


# =============================================================================
# HELPER: Signal'ları aktifleştirmek için apps.py'de kullanın
# =============================================================================
#
# # notifications/apps.py
# class NotificationsConfig(AppConfig):
#     default_auto_field = "django.db.models.BigAutoField"
#     name = "notifications"
#
#     def ready(self):
#         # Signal handler'ları import et
#         import notifications.signals  # noqa
