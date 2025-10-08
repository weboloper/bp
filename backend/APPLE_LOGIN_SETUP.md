# Apple Sign In Setup Guide

## ✅ Apple Login Eklendi!

Apple Sign In artık hem login hem de register sayfalarında mevcut.

## 🎯 Özellikler

- ✅ Apple OAuth 2.0 flow
- ✅ JWT token decode (basit, verification olmadan)
- ✅ İlk login'de isim bilgisi alınır
- ✅ Email otomatik verified
- ✅ Modern siyah Apple butonu
- ✅ CSRF koruması (state parameter)

## 📋 Kurulum Adımları

### 1. Apple Developer Account

1. https://developer.apple.com/ adresine git
2. Apple Developer hesabına giriş yap (ücretli, $99/yıl)

### 2. App ID Oluştur

1. **Certificates, Identifiers & Profiles** > **Identifiers**
2. **+** butonuna tıkla
3. **App IDs** seç
4. **Type**: App
5. **Description**: Uygulama açıklaması
6. **Bundle ID**: com.yourcompany.yourapp (reverse domain)
7. **Capabilities**: "Sign In with Apple" seç
8. **Save**

### 3. Services ID Oluştur (Web için)

1. **Identifiers** > **+**
2. **Services IDs** seç
3. **Description**: Web App Name
4. **Identifier**: com.yourcompany.yourapp.web (farklı olmalı)
5. **Save**

### 4. Services ID'yi Yapılandır

1. Oluşturduğun Services ID'ye tıkla
2. **Sign In with Apple** seç
3. **Configure** buton una tıkla
4. **Primary App ID**: Yukarıda oluşturduğun App ID'yi seç
5. **Website URLs**:
   - **Domains**: `yourdomain.com` (ya da localhost:8000 - development)
   - **Return URLs**: 
     ```
     http://localhost:8000/accounts/apple-callback/
     https://yourdomain.com/accounts/apple-callback/
     ```
6. **Save** > **Continue** > **Save**

### 5. Key Oluştur (Opsiyonel - Server-to-Server için)

**NOT**: Basit implementation'da gerekli değil, ama production için önerilir.

1. **Keys** > **+**
2. **Key Name**: Apple Sign In Key
3. **Sign In with Apple** seç
4. **Configure** > App ID seç > **Save**
5. **Continue** > **Register**
6. **Download** (.p8 dosyası) - BU DOSYAYI GÜVENLİ SAKLA!
7. **Key ID**'yi not al

### 6. Environment Variables

`.env` dosyana ekle:

```bash
# Apple OAuth credentials
APPLE_SERVICE_ID=com.yourcompany.yourapp.web  # Services ID
APPLE_TEAM_ID=ABC123XYZ  # Apple Developer Team ID
APPLE_KEY_ID=ABC123  # Key ID (opsiyonel)
APPLE_PRIVATE_KEY_PATH=/path/to/AuthKey_ABC123.p8  # .p8 file path (opsiyonel)
```

**Team ID'yi bulmak:**
- Apple Developer > Membership > Team ID

## 🔧 Mevcut Implementation

### Basit Yaklaşım (Şu Anki)

```python
# apple_callback_view
# - id_token'dan email decode edilir (JWT decode)
# - Token verify EDİLMEZ (production için güvenli değil!)
# - User oluşturulur/bulunur
# - Login yapılır
```

**장점:**
- ✅ Hızlı setup
- ✅ Kolay test
- ✅ Key dosyası gerekmez

**단점:**
- ❌ Token verify edilmiyor (güvenlik riski)
- ❌ Production için önerilmez

### Production Yaklaşım (Önerilen)

Token verification için `PyJWT` ve `cryptography` kullanmalısın:

```python
import jwt
import requests

# Apple'ın public key'lerini al
apple_keys = requests.get('https://appleid.apple.com/auth/keys').json()

# Token'ı verify et
decoded = jwt.decode(
    id_token,
    apple_public_key,
    algorithms=['RS256'],
    audience=settings.APPLE_SERVICE_ID,
    issuer='https://appleid.apple.com'
)
```

Bu BaseSocialAuth pattern'ine `AppleAuth` class'ında implement edilebilir.

## 🎨 UI

### Login/Register Sayfaları

Her iki sayfada da Apple butonu mevcut:
- Modern siyah buton
- Apple logosu
- "Apple ile Giriş/Kayıt" yazısı
- Google butonunun altında

## 🧪 Test

### Development Test

```bash
# 1. Server başlat
python manage.py runserver

# 2. Tarayıcıda aç
http://localhost:8000/accounts/login/

# 3. "Apple ile Giriş Yap" butonuna tıkla
```

**NOT**: Localhost'ta test etmek için Apple Developer'da localhost URL'i eklemelisin.

### Production Test

```bash
# 1. HTTPS gerekli
https://yourdomain.com/accounts/login/

# 2. "Apple ile Giriş Yap" butonuna tıkla
```

## 🔐 Güvenlik Notları

### Şu Anki Implementation

- ✅ CSRF koruması (state parameter)
- ✅ POST request validation
- ⚠️ Token verify edilmiyor (development için OK, production için NO)

### Production İçin Yapılması Gerekenler

1. **Token Verification**: JWT token'ı Apple public key ile verify et
2. **HTTPS Zorunlu**: Apple Sign In sadece HTTPS'te çalışır
3. **Nonce Ekle**: Replay attack'lara karşı koruma
4. **Client Secret Generate**: Server-to-server token exchange için

## 📚 Dokümantasyon

### Apple Official Docs

- [Sign in with Apple Overview](https://developer.apple.com/sign-in-with-apple/)
- [Configuring Your Webpage](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/configuring_your_webpage_for_sign_in_with_apple)

### Code Examples

**Simple Email Decode:**
```python
import json
import base64

parts = id_token.split('.')
payload = parts[1]
payload += '=' * (4 - len(payload) % 4)
decoded = base64.urlsafe_b64decode(payload)
user_data = json.loads(decoded)
email = user_data.get('email')
```

**Full Verification (Production):**
```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization

# Apple public key al
apple_keys = requests.get('https://appleid.apple.com/auth/keys').json()

# Token verify et
decoded = jwt.decode(
    id_token,
    public_key,
    algorithms=['RS256'],
    audience=APPLE_SERVICE_ID,
    issuer='https://appleid.apple.com'
)
```

## ❓ SSS (FAQ)

### Q: "Invalid client" hatası alıyorum
**A**: Services ID'nin doğru olduğundan emin ol ve web configuration yapıldığından emin ol.

### Q: "Invalid redirect URI" hatası
**A**: Return URL'lerin tam olarak eşleştiğinden emin ol (http:// vs https://, trailing slash)

### Q: İsim bilgileri gelmiyor
**A**: İsim bilgileri SADECE ilk login'de gelir. Sonraki login'lerde gelmez. Cache'le veya sakla.

### Q: Localhost'ta çalışmıyor
**A**: Apple Developer'da localhost URL'ini authorized domains'e eklemelisin.

### Q: Production'da token verify etmeli miyim?
**A**: EVET! Basit decode güvenli değil. JWT verification zorunlu.

## 🔜 Gelecek İyileştirmeler

1. **Token Verification**: PyJWT ile full verification
2. **BaseSocialAuth Integration**: AppleAuth class'ı tam implement et
3. **Nonce Support**: Replay attack koruması
4. **Client Secret**: Server-to-server token exchange
5. **Refresh Token**: Long-lived sessions

## 🎉 Sonuç

Apple Sign In başarıyla eklendi! 

**Development için hazır** ✅
**Production için token verification ekle** ⚠️

---

**Not**: Bu implementation basitleştirilmiştir. Production kullanımı için token verification eklenmeli!
