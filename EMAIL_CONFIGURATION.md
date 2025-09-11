# Email Configuration Guide

Django boilerplate projesi için email konfigürasyon rehberi.

## Email Provider Seçenekleri

### 1. cPanel Email (Önerilen - Başlangıç)
**Avantajlar:**
- ✅ Ücretsiz (hosting ile birlikte gelir)
- ✅ Kolay kurulum
- ✅ Domain'e bağlı profesyonel email adresleri
- ✅ Hemen kullanıma hazır

**Dezavantajlar:**
- ❌ Sınırlı günlük email quota'sı
- ❌ Delivery rate'i profesyonel servislerden düşük
- ❌ Analytics/tracking yok

**Kullanım:**
```bash
# .env dosyasına ekle
EMAIL_PROVIDER=cpanel
EMAIL_HOST=mail.yourdomain.com
EMAIL_HOST_USER=noreply@yourdomain.com
EMAIL_HOST_PASSWORD=your_email_password
```

### 2. Gmail SMTP (Sadece Geliştirme)
**Avantajlar:**
- ✅ Hızlı kurulum
- ✅ Test için ideal

**Dezavantajlar:**
- ❌ **Production'da önerilmez**
- ❌ Günlük 500 email limiti
- ❌ "Less secure apps" ayarı gerekli
- ❌ Google güvenlik politikaları değişebilir
- ❌ Business email olmadığı için spam'e düşme riski

**Kullanım:**
```bash
# .env dosyasına ekle (SADECE DEVELOPMENT)
EMAIL_PROVIDER=gmail
GMAIL_EMAIL=your-gmail@gmail.com
GMAIL_APP_PASSWORD=your_app_specific_password
```

### 3. SendGrid (Önerilen - Production)
**Avantajlar:**
- ✅ 100 email/gün ücretsiz
- ✅ Yüksek delivery rate
- ✅ Analytics ve tracking
- ✅ Template yönetimi
- ✅ Güvenilir ve hızlı

**Dezavantajlar:**
- ❌ API key yönetimi gerekli
- ❌ Ücretli planlar volume artışında

**Kullanım:**
```bash
# .env dosyasına ekle
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
```

### 4. Mailgun (Önerilen - Production)
**Avantajlar:**
- ✅ 5000 email/ay ücretsiz (3 ay)
- ✅ Güçlü API
- ✅ EU server seçeneği
- ✅ Detailed analytics

**Dezavantajlar:**
- ❌ Domain verification süreci uzun
- ❌ Ücretsiz plan sınırlı

**Kullanım:**
```bash
# .env dosyasına ekle
EMAIL_PROVIDER=mailgun
MAILGUN_SMTP_LOGIN=your_smtp_login
MAILGUN_SMTP_PASSWORD=your_smtp_password
MAILGUN_FROM_EMAIL=noreply@yourdomain.com
```

## Email Sending Methods

### 1. Smart Email (Recommended)
Ortama göre otomatik olarak sync/async karar verir:

```python
from core.email_service import EmailService

# Welcome email - app-based template path
EmailService.send_smart_email(
    template_name='accounts/emails/welcome',
    context={'user': user, 'site_name': 'MyProject'},
    subject='Hoş geldiniz!',
    recipient_list=[user.email]
)
```

### 2. Critical Email (Always Sync)
Verification, password reset gibi kritik emailler için:

```python
# Critical email - her zaman senkron gönderilir
EmailService.send_critical_email(
    template_name='accounts/emails/verification',
    context={
        'user': user,
        'verification_link': verification_url
    },
    subject='Email adresinizi doğrulayın',
    recipient_list=[user.email]
)
```

### 3. Force Sync (Special Cases)
Normal email'i senkron göndermeye zorlamak için:

```python
# Force sync - özel durumlar için
EmailService.send_smart_email(
    template_name='orders/emails/confirmation',
    context={'order': order, 'user': user},
    subject='Sipariş onaylandı',
    recipient_list=[user.email],
    force_sync=True  # Manuel olarak sync'e zorla
)
```

#### Force Sync Ne Zaman Kullanılır?

| Durum | Örnek | Neden Force Sync |
|-------|-------|------------------|
| **Sipariş işlemleri** | Order confirmation, payment success | Kullanıcı sonucu hemen görmek ister |
| **Acil bildirimler** | Security alert, account locked | Anında bildirilmesi gerekir |
| **API yanıtları** | Contact form, support ticket | API response'da email durumu döndürülecek |
| **Gerçek zamanlı** | Live event notifications | Zamanlama kritik |
| **Error recovery** | Async başarısız olan emailler | Fallback olarak |

#### Normal Smart Email vs Force Sync:

```python
# ✅ Normal - async olabilir (önerilir)
EmailService.send_smart_email(
    template_name='marketing/emails/newsletter',
    context={'articles': articles},
    subject='Haftalık bülten',
    recipient_list=subscribers
)

# ⚡ Force Sync - kullanıcı bekliyor
EmailService.send_smart_email(
    template_name='downloads/emails/ready',
    context={'file_url': download_url},
    subject='Dosyanız hazır',
    recipient_list=[user.email],
    force_sync=True  # Kullanıcı download linkini bekliyor
)
```

## Environment Variables

### Development (.env)
```bash
DEBUG=True
USE_ASYNC_EMAIL=False
EMAIL_PROVIDER=console  # Console'a yazar, email göndermez
```

### Staging (.env.staging)
```bash
DEBUG=False
USE_ASYNC_EMAIL=True
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your_test_api_key
SENDGRID_FROM_EMAIL=staging@yourdomain.com
```

### Production (.env.prod)
```bash
DEBUG=False
USE_ASYNC_EMAIL=True
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your_production_api_key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com
```

### cPanel Production (.env.prod)
```bash
DEBUG=False
USE_ASYNC_EMAIL=False  # cPanel'de Celery yok
EMAIL_PROVIDER=cpanel
EMAIL_HOST=mail.yourdomain.com
EMAIL_HOST_USER=noreply@yourdomain.com
EMAIL_HOST_PASSWORD=your_cpanel_email_password
```

## Kullanım Örnekleri

### Registration Email
```python
# accounts/views.py
from core.email_service import EmailService

def register_user(request):
    # ... user creation logic
    
    # Welcome email - non-critical, can be async
    EmailService.send_smart_email(
        template_name='accounts/emails/welcome',
        context={
            'user': user,
            'username': user.username,
            'login_url': request.build_absolute_uri('/login/')
        },
        subject='Hoş geldiniz!',
        recipient_list=[user.email]
    )
```

### Email Verification
```python
# accounts/views.py
def send_verification_email(request):
    # Verification email - critical, must be sync
    EmailService.send_critical_email(
        template_name='accounts/emails/verification',
        context={
            'user': request.user,
            'verification_link': verification_url,
            'expires_in': '24 saat'
        },
        subject='Email adresinizi doğrulayın',
        recipient_list=[request.user.email]
    )
```

### Password Reset
```python
# accounts/views.py
def password_reset(request):
    # Password reset - critical, must be sync
    EmailService.send_critical_email(
        template_name='accounts/emails/password_reset',
        context={
            'user': user,
            'reset_link': reset_url,
            'expires_in': '1 saat'
        },
        subject='Şifre sıfırlama talebi',
        recipient_list=[user.email]
    )
```

### Order Confirmation (Force Sync Example)
```python
# orders/views.py
def complete_order(request):
    # Order confirmation - user expects immediate email
    EmailService.send_smart_email(
        template_name='orders/emails/confirmation',
        context={
            'order': order,
            'user': user,
            'total': order.total,
            'items': order.items.all()
        },
        subject=f'Sipariş #{order.id} onaylandı',
        recipient_list=[user.email],
        force_sync=True  # User is waiting for confirmation
    )
```

### Newsletter (Async Example)
```python
# marketing/views.py
def send_newsletter(request):
    # Newsletter - can be async, not urgent
    EmailService.send_smart_email(
        template_name='marketing/emails/newsletter',
        context={
            'articles': latest_articles,
            'unsubscribe_link': unsubscribe_url
        },
        subject='Haftalık bülten',
        recipient_list=subscriber_emails
        # No force_sync - will use USE_ASYNC_EMAIL setting
    )
```

## Template Structure

Email template'leri her app'in kendi template klasöründe saklanır (App-based):

```
# App-based Template Structure (Recommended for Boilerplate)
accounts/
└── templates/
    └── accounts/
        └── emails/
            ├── welcome.html           # Welcome email
            ├── verification.html      # Email verification  
            └── password_reset.html    # Password reset

orders/
└── templates/
    └── orders/
        └── emails/
            ├── confirmation.html      # Order confirmation
            └── shipped.html           # Shipment notification

marketing/
└── templates/
    └── marketing/
        └── emails/
            ├── newsletter.html        # Newsletter
            └── promotion.html         # Promotional email

# Global email base template
templates/
└── email_base.html                   # Base email template
```

### Template Path Examples:
```python
# App-based paths (Recommended)
'accounts/emails/welcome'           # accounts/templates/accounts/emails/welcome.html
'accounts/emails/verification'      # accounts/templates/accounts/emails/verification.html
'orders/emails/confirmation'        # orders/templates/orders/emails/confirmation.html
'marketing/emails/newsletter'       # marketing/templates/marketing/emails/newsletter.html
```

### Template Inheritance:
```html
<!-- accounts/templates/accounts/emails/welcome.html -->
{% extends 'email_base.html' %}

{% block email_title %}Hoş Geldiniz!{% endblock %}

{% block email_content %}
<h2>Merhaba {{ user.username }}!</h2>
<p>Platformumuza hoş geldiniz...</p>
{% endblock %}
```

## Provider Setup Guide

### SendGrid Setup
1. SendGrid'e kayıt ol
2. API Key oluştur
3. Domain verification yap
4. `.env` dosyasına API key ekle

### Mailgun Setup
1. Mailgun'a kayıt ol
2. Domain ekle ve DNS ayarlarını yap
3. SMTP credentials al
4. `.env` dosyasına bilgileri ekle

### cPanel Setup
1. cPanel Email Accounts'tan email oluştur
2. Email ayarlarından SMTP bilgilerini al
3. `.env` dosyasına bilgileri ekle

## Best Practices

1. **Critical emails her zaman sync** - verification, password reset
2. **Marketing emails async** - newsletter, promotional
3. **Production'da Gmail kullanma**
4. **Template-based emails kullan** - consistency için
5. **Error handling ekle** - email delivery failure'larını handle et
6. **Rate limiting uygula** - spam prevention için