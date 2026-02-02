# Google OAuth Login Kurulumu

Bu dosya, Google OAuth login entegrasyonunu nasıl kuracağınızı açıklar.

## 1. Google Cloud Console'da Proje Oluşturma

1. [Google Cloud Console](https://console.cloud.google.com/) adresine gidin
2. Yeni bir proje oluşturun veya mevcut projeyi seçin
3. Sol menüden **"APIs & Services"** > **"Credentials"** seçin

## 2. OAuth 2.0 Client ID Oluşturma

1. **"Create Credentials"** butonuna tıklayın
2. **"OAuth client ID"** seçin
3. **Application type** olarak **"Web application"** seçin
4. **Name** alanına bir isim verin (örn: "BP Django App")

### Authorized redirect URIs

Aşağıdaki URL'leri ekleyin:

**Development:**
```
http://localhost:8000/accounts/google-callback/
http://127.0.0.1:8000/accounts/google-callback/
```

**Production:**
```
https://yourdomain.com/accounts/google-callback/
```

5. **"Create"** butonuna tıklayın
6. Client ID ve Client Secret'i kopyalayın

## 3. Environment Variables (.env dosyası)

`.env` dosyanıza aşağıdaki satırları ekleyin:

```bash
# Google OAuth Credentials
GOOGLE_OAUTH2_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GOOGLE_OAUTH2_CLIENT_SECRET=your_client_secret_here
```

## 4. Requests Kütüphanesini Yükleme

Eğer yüklü değilse:

```bash
pip install requests
```

## 5. Test Etme

1. Django sunucusunu başlatın:
```bash
python manage.py runserver
```

2. Tarayıcıda şu adreslere gidin:
   - Login: http://localhost:8000/accounts/login/
   - Register: http://localhost:8000/accounts/register/

3. "Google ile Giriş Yap" butonuna tıklayın

## 6. Nasıl Çalışır?

### Frontend (Template) Flow:

1. Kullanıcı "Google ile Giriş Yap" butonuna tıklar
2. `google_login_view` tetiklenir
3. Google OAuth URL'ine yönlendirilir
4. Kullanıcı Google hesabı ile giriş yapar
5. Google, kullanıcıyı `google_callback_view`'e geri yönlendirir
6. Callback view:
   - Authorization code'u access token ile değiştirir
   - Access token ile kullanıcı bilgilerini alır
   - Kullanıcı varsa login eder, yoksa oluşturur
   - Kullanıcı profile sayfasına yönlendirilir

### API Flow (Mevcut):

API endpoint'i şu şekilde çalışır:
- Frontend, Google'dan direkt access token alır
- Access token'ı `/api/accounts/auth/social/google/` endpoint'ine gönderir
- Backend, token'ı verify eder ve JWT token döner

## 7. Önemli Notlar

- **CSRF Koruması:** State parametresi ile CSRF saldırılarına karşı korunur
- **Email Doğrulama:** Google ile giriş yapan kullanıcılar otomatik doğrulanmış sayılır (`is_verified=True`)
- **Unique Username:** Email'in @ işaretinden önceki kısmı username olarak kullanılır. Çakışma varsa numara eklenir
- **Profile Oluşturma:** Yeni kullanıcılar için otomatik profil oluşturulur
- **Development:** Localhost URL'lerini authorized redirect URIs'e eklemeyi unutmayın
- **Production:** HTTPS kullanın ve domain'inizi ekleyin

## 8. Hata Ayıklama

Eğer sorun yaşarsanız:

1. **Google Cloud Console'da URL'leri kontrol edin**
   - Redirect URI'ler tam olarak eşleşmeli (sonundaki `/` dahil)

2. **Environment variables'ı kontrol edin**
   ```python
   python manage.py shell
   >>> from django.conf import settings
   >>> print(settings.GOOGLE_OAUTH2_CLIENT_ID)
   >>> print(settings.GOOGLE_OAUTH2_CLIENT_SECRET)
   ```

3. **Console loglarını kontrol edin**
   - Django sunucu logları
   - Tarayıcı console logları

4. **State parametresi hatası alırsanız**
   - Session'ların çalıştığından emin olun
   - Cookies'in etkinleştirildiğinden emin olun

## 9. Güvenlik Tavsiyeleri

- Client Secret'i asla git'e commit etmeyin
- Production'da `.env` dosyasını güvenli tutun
- HTTPS kullanın
- State parametresini her zaman doğrulayın
- Access token'ları güvenli bir şekilde saklayın

## 10. İleri Düzey Özellikler

### Profil Resmi Ekleme

Google'dan profil resmini de alabilirsiniz:

```python
# google_callback_view içinde
if user_data.get('picture'):
    # Avatar URL'sini profile kaydet
    profile.avatar_url = user_data['picture']
    profile.save()
```

### Ek Scopelar

Daha fazla bilgi almak için scope'ları genişletin:

```python
'scope': 'openid email profile https://www.googleapis.com/auth/userinfo.profile',
```

### Refresh Token

Offline access için:

```python
'access_type': 'offline',
'prompt': 'consent'
```

## Destek

Sorun yaşarsanız:
- Django loglarını kontrol edin
- Google Cloud Console'da audit loglarına bakın
- Stack Overflow'da arama yapın
