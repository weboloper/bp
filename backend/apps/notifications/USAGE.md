# Notifications Module - Usage Guide

Bu dokümantasyon, notifications modülünün kullanım örneklerini içerir.

## Kurulum

```python
# settings.py INSTALLED_APPS
INSTALLED_APPS = [
    # ...
    'providers',          # SMS/Email provider infrastructure
    'notifications',      # Notifications (SMS, Email, In-App)
]
```

```bash
# Migration
python manage.py makemigrations providers notifications
python manage.py migrate
```

---

## 1. Template ile Bildirim (Önerilen Yöntem)

En yaygın kullanım şekli. Template'ler Django Admin'den yönetilir.

```python
from notifications.services import notify

# Randevu hatırlatma (SMS + Email + In-App)
result = notify(
    code="appointment_reminder",
    tenant=company,
    recipient=client,  # Client veya User instance
    context={
        "client_name": client.full_name,
        "date": "15 Ocak 2025",
        "time": "14:00",
        "service": "Saç Kesimi",
        "company_name": company.name,
        "company_phone": company.phone,
    }
)

print(result)
# {
#     "success": True,
#     "channels": {
#         "sms": {"success": True, "outbound_id": 123, "credits_used": 1},
#         "email": {"success": True, "outbound_id": 124}
#     }
# }
```

### Belirli Kanalları Geçersiz Kılma

```python
# Sadece SMS gönder (template'de email de aktif olsa bile)
result = notify(
    code="appointment_reminder",
    tenant=company,
    recipient=client,
    context={...},
    channels=["sms"]  # Sadece SMS
)
```

### Gönderen Bilgisi Ekleme

```python
result = notify(
    code="appointment_reminder",
    tenant=company,
    recipient=client,
    context={...},
    sent_by=request.user  # Kim gönderdi
)
```

---

## 2. Direkt In-App Bildirim

Template kullanmadan doğrudan in-app bildirim oluşturur.

### Tek Kullanıcıya

```python
from notifications.services import NotificationDispatcher

# Staff'a bildirim
NotificationDispatcher.notify_user(
    user=staff.user,
    notification_type="appointment_new",
    title="Yeni Randevu",
    message=f"{client.full_name} - 15 Ocak 14:00",
    tenant=company,
    sender_user=request.user,
    action_url=f"/appointments/{appointment.id}",
    action_label="Görüntüle",
    related_object=appointment,  # GenericForeignKey
    priority="high",
    metadata={"appointment_id": appointment.id}
)
```

### Tüm Tenant Kullanıcılarına (Broadcast)

```python
from notifications.services import NotificationDispatcher

# Yeni randevu - tüm staff'a bildir
NotificationDispatcher.notify_tenant_users(
    tenant=company,
    notification_type="appointment_new",
    title="Yeni Randevu",
    message=f"{client.full_name} - 15 Ocak 14:00 - Saç Kesimi",
    exclude_user=request.user,  # Oluşturan kullanıcı hariç
    action_url=f"/appointments/{appointment.id}",
    related_object=appointment
)
```

---

## 3. System Bildirimi

Platform tarafından gönderilen bildirimler (tenant bağımsız).

```python
from notifications.services import NotificationDispatcher

# SMS kredisi uyarısı
NotificationDispatcher.system_notify_user(
    user=tenant_owner,
    notification_type="sms_credit_low",
    title="SMS Krediniz Azalıyor",
    message=f"Kalan krediniz: {balance}. Hemen yükleyin!",
    priority="high",
    action_url="/settings/billing/sms",
    action_label="Kredi Yükle"
)

# Sistem duyurusu
NotificationDispatcher.system_notify_user(
    user=user,
    notification_type="system_announcement",
    title="Yeni Özellik!",
    message="Artık toplu SMS gönderebilirsiniz.",
    priority="normal"
)
```

---

## 4. Doğrudan Channel Kullanımı

Template olmadan doğrudan SMS/Email gönderimi.

### SMS Gönderme

```python
from notifications.channels import get_channel
from notifications.constants import Channel

sms_channel = get_channel(Channel.SMS)

result = sms_channel.send(
    recipient="5551234567",
    content={"content": "Merhaba, randevunuz onaylandı."},
    tenant=company,
    client=client,  # Opsiyonel - OutboundMessage'da client FK için
    sent_by=request.user,
    notification_type="custom",
    check_credit=True  # Kredi kontrolü (default: True)
)

print(result)
# {
#     "success": True,
#     "outbound_id": 125,
#     "message_id": "MOCK_ABC123",
#     "credits_used": 1
# }
```

### Email Gönderme

```python
from notifications.channels import get_channel
from notifications.constants import Channel

email_channel = get_channel(Channel.EMAIL)

result = email_channel.send(
    recipient="client@example.com",
    content={
        "subject": "Randevu Onayı",
        "body_text": "Randevunuz onaylanmıştır.",
        "body_html": "<h1>Randevunuz onaylanmıştır.</h1>"
    },
    tenant=company,
    client=client,
    sent_by=request.user,
    notification_type="appointment_confirmation"
)
```

### In-App Bildirim

```python
from notifications.channels import get_channel
from notifications.constants import Channel

in_app_channel = get_channel(Channel.IN_APP)

result = in_app_channel.send(
    recipient=user,  # User instance
    content={
        "title": "Yeni Görev",
        "message": "Size yeni bir görev atandı."
    },
    tenant=company,
    sender_user=admin_user,
    notification_type="task_assigned",
    priority="high",
    action_url="/tasks/123",
    action_label="Görevi Aç",
    related_object=task
)
```

---

## 5. Provider Doğrudan Kullanımı

Düşük seviye SMS/Email API'si.

### SMS Provider

```python
from providers.sms import get_sms_provider

provider = get_sms_provider()

# Tekli SMS
result = provider.send(
    phone="5551234567",
    message="Test mesajı",
    sender_id="SALON"  # Opsiyonel
)

print(result)
# SMSResult(success=True, message_id="123", status=SMSStatus.SENT, credits_used=1)

# Toplu SMS
bulk_result = provider.send_bulk(
    recipients=["5551234567", "5559876543"],
    message="Kampanya mesajı",
    sender_id="SALON"
)

print(bulk_result)
# BulkSMSResult(success=True, batch_id="456", total=2, successful=2, failed=0, credits_used=2)

# Bakiye sorgulama
balance = provider.get_balance()
# {"success": True, "provider": "netgsm", "balance": 1000.0, "currency": "TL"}

# Kredi hesaplama
credits = provider.calculate_credits("Merhaba dünya")  # 1
credits = provider.calculate_credits("Türkçe karakterli mesaj: çğışöü")  # 1 (UCS2)
```

### Email Provider

```python
from providers.email import get_email_provider

provider = get_email_provider()

result = provider.send(
    to_email="client@example.com",
    subject="Hoş Geldiniz",
    body_text="Salonumuza hoş geldiniz!",
    body_html="<h1>Salonumuza hoş geldiniz!</h1>",
    from_email="noreply@salon.com",
    from_name="Salon App"
)

print(result)
# EmailResult(success=True, message_id="abc123", status=EmailStatus.SENT)
```

---

## 6. API Kullanımı

REST API üzerinden bildirim gönderme.

### Template ile Gönderim

```http
POST /api/v1/notifications/send/
Authorization: Bearer <token>
Content-Type: application/json

{
    "code": "appointment_reminder",
    "recipient_type": "client",
    "recipient_id": 123,
    "context": {
        "client_name": "Ahmet",
        "date": "15 Ocak",
        "time": "14:00"
    },
    "channels": ["sms"]  // Opsiyonel
}
```

### Doğrudan SMS

```http
POST /api/v1/notifications/send/sms/
Authorization: Bearer <token>
Content-Type: application/json

{
    "phone": "5551234567",
    "message": "Randevunuz onaylandı.",
    "client_id": 123  // Opsiyonel
}
```

### Doğrudan Email

```http
POST /api/v1/notifications/send/email/
Authorization: Bearer <token>
Content-Type: application/json

{
    "email": "client@example.com",
    "subject": "Randevu Onayı",
    "body_text": "Randevunuz onaylanmıştır.",
    "body_html": "<h1>Onaylandı</h1>",
    "client_id": 123  // Opsiyonel
}
```

### SMS Kredi Kontrolü

```http
GET /api/v1/notifications/sms/balance/
Authorization: Bearer <token>

Response:
{
    "tenant_credits": 500,
    "provider_balance": {"success": true, "balance": 1000, "currency": "TL"}
}
```

### SMS Kredi Hesaplama

```http
POST /api/v1/notifications/sms/calculate/
Authorization: Bearer <token>
Content-Type: application/json

{
    "message": "Türkçe karakterli mesaj: çğışöü"
}

Response:
{
    "message_length": 32,
    "credits_needed": 1,
    "encoding": "UCS2",
    "has_turkish_chars": true
}
```

---

## 7. Signal Handler Örneği

Otomatik bildirim gönderimi için signal kullanımı.

```python
# appointments/signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender='appointments.Appointment')
def notify_on_new_appointment(sender, instance, created, **kwargs):
    if not created:
        return

    from notifications.services import notify, NotificationDispatcher

    # Müşteriye SMS/Email
    notify(
        code='appointment_confirmation',
        tenant=instance.company,
        recipient=instance.client,
        context={
            'client_name': instance.client.first_name,
            'date': instance.start_time.strftime('%d.%m.%Y'),
            'time': instance.start_time.strftime('%H:%M'),
            'service': instance.service.name,
        }
    )

    # Staff'a in-app bildirim
    if instance.staff and instance.staff.user:
        NotificationDispatcher.notify_user(
            user=instance.staff.user,
            notification_type='appointment_new',
            title='Yeni Randevu',
            message=f'{instance.client.full_name} - {instance.start_time.strftime("%H:%M")}',
            tenant=instance.company,
            related_object=instance
        )
```

---

## 8. Template Değişkenleri

Template'lerde kullanılabilecek örnek değişkenler:

### Randevu Template'leri
```
{{ client_name }}      - Müşteri adı
{{ date }}             - Tarih
{{ time }}             - Saat
{{ service }}          - Hizmet adı
{{ staff_name }}       - Personel adı
{{ company_name }}     - İşletme adı
{{ company_phone }}    - İşletme telefonu
{{ company_address }}  - İşletme adresi
```

### Doğum Günü Template'i
```
{{ client_name }}      - Müşteri adı
{{ discount_code }}    - İndirim kodu
{{ discount_percent }} - İndirim yüzdesi
```

### Kampanya Template'i
```
{{ client_name }}      - Müşteri adı
{{ campaign_title }}   - Kampanya başlığı
{{ campaign_details }} - Kampanya detayları
{{ valid_until }}      - Geçerlilik tarihi
```

---

## 9. Notification Types

Kullanılabilir bildirim tipleri (`notifications/constants.py`):

### System → Tenant
- `system_announcement` - Sistem duyurusu
- `billing_alert` - Fatura uyarısı
- `sms_credit_low` - SMS kredisi düşük
- `sms_credit_depleted` - SMS kredisi bitti
- `subscription_expiry` - Abonelik bitiyor
- `subscription_expired` - Abonelik bitti
- `feature_update` - Yeni özellik

### Tenant → Staff (In-App)
- `appointment_new` - Yeni randevu
- `appointment_cancelled` - Randevu iptal
- `appointment_updated` - Randevu güncellendi
- `appointment_reminder_staff` - Personel randevu hatırlatma
- `client_new` - Yeni müşteri
- `task_assigned` - Görev atandı

### Tenant → Client (SMS/Email)
- `appointment_confirmation` - Randevu onayı
- `appointment_reminder` - Randevu hatırlatma
- `appointment_cancelled_client` - Randevu iptal (müşteri)
- `birthday_greeting` - Doğum günü
- `campaign` - Kampanya
- `feedback_request` - Geri bildirim talebi
- `custom` - Özel mesaj

---

## 10. SMS Gönderim Akışı (Architecture)

### Akış Diyagramı

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SMS GÖNDERİM AKIŞI                                │
└─────────────────────────────────────────────────────────────────────────────┘

  Uygulama Katmanı                    Servis Katmanı                Provider Katmanı
  ─────────────────                   ──────────────                ────────────────

  ┌──────────────┐
  │   View /     │
  │   Signal /   │
  │   Task       │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐     ┌─────────────────────────────────────────────────────────┐
  │   notify()   │────▶│  notifications/services/dispatcher.py                   │
  │              │     │                                                          │
  │  veya        │     │  1. Template'i çözümle (code → NotificationTemplate)    │
  │              │     │  2. İçeriği render et (context → message)               │
  │  send_sms()  │     │  3. Aktif kanalları belirle (sms/email/in_app)          │
  └──────────────┘     └───────────────────────┬─────────────────────────────────┘
                                               │
                                               ▼
                       ┌─────────────────────────────────────────────────────────┐
                       │  notifications/channels/sms.py (SMSChannel)             │
                       │                                                          │
                       │  1. Telefon numarası validasyonu                        │
                       │  2. Kredi hesaplama (calculate_credits)                 │
                       │  3. Kredi kontrolü ──────────────────┐                  │
                       │  4. OutboundMessage kaydı oluştur    │                  │
                       │  5. Provider'a gönder                │                  │
                       │  6. Başarılıysa kredi düş ───────────┤                  │
                       │  7. OutboundMessage güncelle         │                  │
                       └──────────────────────┬───────────────┼──────────────────┘
                                              │               │
                    ┌─────────────────────────┘               │
                    │                                         │
                    ▼                                         ▼
  ┌─────────────────────────────────┐       ┌─────────────────────────────────┐
  │  providers/sms/__init__.py      │       │  billing/services/sms.py        │
  │                                 │       │                                  │
  │  get_sms_provider()             │       │  SmsService:                     │
  │         │                       │       │  - has_sufficient_balance()     │
  │         ▼                       │       │  - get_balance()                │
  │  providers/registry.py          │       │  - deduct_credits_bulk()        │
  │  get_sms_backend()              │       │  - add_credits()                │
  │         │                       │       │  - refund_credit()              │
  │         ▼                       │       │                                  │
  │  ┌─────────────────────┐        │       │  Models:                         │
  │  │ settings.SMS_PROVIDER│       │       │  - SmsBalance                    │
  │  │ (netgsm/twilio/mock)│        │       │  - SmsTransaction                │
  │  └─────────┬───────────┘        │       └─────────────────────────────────┘
  │            │                    │
  │            ▼                    │
  │  ┌─────────────────────────┐    │
  │  │ NetGSMProvider          │    │
  │  │ TwilioProvider          │    │
  │  │ MockSMSProvider         │    │
  │  └─────────┬───────────────┘    │
  │            │                    │
  └────────────┼────────────────────┘
               │
               ▼
  ┌─────────────────────────────────┐
  │  SMSResult                      │
  │  - success: bool                │
  │  - message_id: str              │
  │  - status: SMSStatus            │
  │  - credits_used: int            │
  │  - error_message: str           │
  └─────────────────────────────────┘
```

### Provider Yapılandırması

Provider'lar **settings.py** üzerinden yapılandırılır (database tabanlı değil):

```python
# config/settings.py

# SMS Provider
SMS_PROVIDER = env('SMS_PROVIDER', default='mock')  # mock, netgsm, twilio

# NetGSM (Production)
NETGSM_USERCODE = env('NETGSM_USERCODE', default='')
NETGSM_PASSWORD = env('NETGSM_PASSWORD', default='')
NETGSM_MSGHEADER = env('NETGSM_MSGHEADER', default='')

# Twilio (Alternative)
TWILIO_ACCOUNT_SID = env('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = env('TWILIO_AUTH_TOKEN', default='')
TWILIO_FROM_NUMBER = env('TWILIO_FROM_NUMBER', default='')

# Email Provider
EMAIL_PROVIDER = env('EMAIL_PROVIDER', default='mock')  # mock, smtp, sendgrid
```

### Provider Registry

```python
# providers/registry.py

BACKEND_MAP = {
    'sms': {
        'netgsm': 'providers.sms.netgsm.NetGSMProvider',
        'twilio': 'providers.sms.twilio.TwilioProvider',
        'mock': 'providers.sms.mock.MockSMSProvider',
    },
    'email': {
        'smtp': 'providers.email.smtp.SMTPProvider',
        'sendgrid': 'providers.email.sendgrid.SendgridProvider',
        'mock': 'providers.email.mock.MockEmailProvider',
    }
}
```

### Billing Entegrasyonu

SMS gönderiminde kredi yönetimi `billing` app tarafından sağlanır:

```
billing/
├── models.py           # SmsBalance, SmsTransaction
└── services/
    ├── __init__.py     # Export: SmsService, InsufficientSmsCredit
    ├── sms.py          # SmsService class
    ├── payment.py      # PaymentService
    ├── subscription.py # SubscriptionService
    └── iyzico.py       # IyzicoService (payment gateway)
```

**Kredi Akışı:**

```python
# 1. Gönderim öncesi kontrol (notifications/channels/sms.py:64)
if not SmsService.has_sufficient_balance(tenant, credits_needed):
    return {'success': False, 'error': 'Insufficient SMS credits'}

# 2. Başarılı gönderim sonrası düşüm (notifications/channels/sms.py:101)
SmsService.deduct_credits_bulk(
    tenant=tenant,
    amount=credits_needed,
    description=f"SMS: {recipient}",
    metadata={'outbound_id': outbound.id}
)
```

**Transaction Tipleri:**

| Tip | Açıklama | amount |
|-----|----------|--------|
| `purchase` | Kredi satın alma | +N |
| `usage` | SMS gönderim kullanımı | -N |
| `refund` | İade | +N |

### Dosya Yapısı

```
notifications/
├── services/
│   ├── __init__.py      # Export: notify, send_sms, send_email, ...
│   └── dispatcher.py    # NotificationDispatcher, send_sms(), send_email()
├── channels/
│   ├── __init__.py      # get_channel()
│   ├── base.py          # BaseChannel
│   ├── sms.py           # SMSChannel (billing entegrasyonu burada)
│   ├── email.py         # EmailChannel
│   └── in_app.py        # InAppChannel
├── models.py            # OutboundMessage, NotificationTemplate, ...
└── constants.py         # Channel, DeliveryStatus, NotificationType

providers/
├── __init__.py
├── registry.py          # get_sms_backend(), get_email_backend()
├── sms/
│   ├── __init__.py      # get_sms_provider()
│   ├── base.py          # BaseSMSProvider, SMSResult, SMSStatus
│   ├── netgsm.py        # NetGSMProvider
│   ├── twilio.py        # TwilioProvider
│   └── mock.py          # MockSMSProvider
└── email/
    ├── __init__.py      # get_email_provider()
    ├── base.py          # BaseEmailProvider, EmailResult, EmailStatus
    ├── smtp.py          # SMTPProvider
    ├── sendgrid.py      # SendgridProvider
    └── mock.py          # MockEmailProvider

billing/
├── models.py            # SmsBalance, SmsTransaction, Payment, ...
└── services/
    ├── __init__.py
    ├── sms.py           # SmsService, InsufficientSmsCredit
    ├── payment.py
    ├── subscription.py
    └── iyzico.py
```

---

## 11. Best Practices

1. **Template kullanın**: Mümkün olduğunca `notify()` fonksiyonunu template ile kullanın. Bu sayede içerikler admin'den yönetilebilir.

2. **Context'i tam verin**: Template'de kullanılan tüm değişkenleri context'e ekleyin.

3. **Kredi kontrolü**: SMS göndermeden önce kredi kontrolü otomatik yapılır, ama toplu gönderimlerde önce kontrol edin.

4. **Hata yönetimi**: `result['success']` değerini kontrol edin ve hataları loglayın.

5. **Signal kullanımı**: Otomatik bildirimler için Django signals kullanın.

6. **Test ortamı**: Development'ta `MockSMSProvider` ve `MockEmailProvider` otomatik kullanılır.

```python
# Hata kontrolü örneği
result = notify(code="...", ...)

if not result['success']:
    logger.error(f"Notification failed: {result.get('error')}")

for channel, channel_result in result.get('channels', {}).items():
    if not channel_result.get('success'):
        logger.warning(f"{channel} failed: {channel_result.get('error')}")
```
