Django REST API projenize çoklu dil desteği eklemek için detaylı bir plan hazırlıyorum:

## Multi-Language Desteği Uygulama Planı

### 1. **Kurulum ve Konfigürasyon**

**Gerekli Paketler:**

```bash
pip install django
# Django'nun i18n desteği built-in gelir
```

**settings.py Düzenlemeleri:**

```python
# Dil ayarları
LANGUAGE_CODE = 'tr'  # Default dil Türkçe
LANGUAGES = [
    ('tr', 'Türkçe'),
    ('en', 'English'),
]

# i18n/l10n ayarları
USE_I18N = True
USE_L10N = True

# Çeviri dosyalarının konumu
LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# Middleware'e LocaleMiddleware ekle (MIDDLEWARE listesinde)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',  # Bu satırı ekle
    'django.middleware.common.CommonMiddleware',
    # ... diğerleri
]
```

### 2. **Kod Tarafında Yapılacaklar**

**Models, Views, Serializers'da Mesajları İşaretle:**

```python
from django.utils.translation import gettext_lazy as _

# Models'da
class Appointment(models.Model):
    # choices için
    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('confirmed', _('Confirmed')),
        ('cancelled', _('Cancelled')),
    ]

    # verbose_name için
    class Meta:
        verbose_name = _('Appointment')
        verbose_name_plural = _('Appointments')

# Views/Serializers'da
from rest_framework import status
from rest_framework.response import Response

def my_view(request):
    return Response({
        'message': _('Appointment created successfully')
    })
```

**Validation Mesajları:**

```python
from django.utils.translation import gettext_lazy as _

class AppointmentSerializer(serializers.ModelSerializer):
    def validate_date(self, value):
        if value < timezone.now().date():
            raise serializers.ValidationError(
                _('Appointment date cannot be in the past')
            )
        return value
```

### 3. **Çeviri Dosyalarının Oluşturulması**

**Komutlar:**

```bash
# Proje root dizininde locale klasörü oluştur
mkdir locale

# Çeviri dosyalarını oluştur
python manage.py makemessages -l tr
python manage.py makemessages -l en

# Compile et
python manage.py compilemessages
```

**Oluşan Dosya Yapısı:**

```
locale/
├── tr/
│   └── LC_MESSAGES/
│       ├── django.po
│       └── django.mo
└── en/
    └── LC_MESSAGES/
        ├── django.po
        └── django.mo
```

### 4. **API'de Dil Seçimi**

**3 Farklı Yöntem:**

**A) Header ile (Önerilen):**

```python
# Client tarafından gönderilecek header:
# Accept-Language: tr
# Accept-Language: en
```

**B) Query Parameter ile:**

```python
# urls.py
from django.conf.urls.i18n import i18n_patterns

# API çağrısı: /api/appointments/?lang=tr
```

**C) Custom Middleware (Daha fazla kontrol için):**

```python
# middleware.py
from django.utils import translation

class LanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Header'dan dil al
        lang = request.META.get('HTTP_ACCEPT_LANGUAGE', 'tr')
        if lang in ['tr', 'en']:
            translation.activate(lang)
            request.LANGUAGE_CODE = lang

        response = self.get_response(request)
        translation.deactivate()
        return response
```

### 5. **Uygulama Adımları (Sırayla)**

1. **settings.py'yi düzenle** (yukarıdaki ayarları ekle)
2. **Tüm mesajları işaretle**: Models, views, serializers, validators'daki tüm string'leri `_()` ile sarmal
3. **Çeviri dosyalarını oluştur**: `makemessages` komutunu çalıştır
4. **locale/tr/LC_MESSAGES/django.po dosyasını doldur**:
   ```
   msgid "Appointment created successfully"
   msgstr "Randevu başarıyla oluşturuldu"
   ```
5. **locale/en/LC_MESSAGES/django.po dosyasını doldur** (İngilizce mesajlar aynı kalacak)
6. **Compile et**: `compilemessages` komutunu çalıştır
7. **Test et**: Farklı dil header'ları ile API çağrıları yap

### 6. **Örnek Kullanım Senaryoları**

**Client Tarafından API Çağrısı:**

```javascript
// Türkçe için
fetch("http://api.example.com/appointments/", {
  headers: {
    "Accept-Language": "tr",
    "Content-Type": "application/json",
  },
});

// İngilizce için
fetch("http://api.example.com/appointments/", {
  headers: {
    "Accept-Language": "en",
    "Content-Type": "application/json",
  },
});
```

### 7. **Best Practices**

- ✅ Tüm kullanıcıya dönük mesajları `gettext_lazy` ile işaretle
- ✅ Model field isimleri yerine `verbose_name` kullan
- ✅ Hard-coded string'leri önle
- ✅ Her yeni mesaj eklediğinde `makemessages` ve `compilemessages` çalıştır
- ✅ `.po` dosyalarını versiyon kontrolüne ekle, `.mo` dosyalarını .gitignore'a ekle

Bu plan ile temiz, sürdürülebilir ve profesyonel bir çoklu dil desteği oluşturabilirsiniz. Hangi adımla başlamak istersiniz?
