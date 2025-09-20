# Social Login Frontend Integration Guide (Devamı)

### Frontend Test
```javascript
// Browser console'da test
localStorage.setItem('access_token', 'your-jwt-token');
fetch('/api/accounts/me/', {
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('access_token') }
}).then(r => r.json()).then(console.log);
```

## Production Deployment Checklist

### 1. Google Console Setup
- [ ] Create project at https://console.developers.google.com
- [ ] Enable Google+ API
- [ ] Create OAuth 2.0 credentials
- [ ] Add authorized origins: https://yourdomain.com
- [ ] Add authorized redirect URIs
- [ ] Set up consent screen

### 2. Facebook Developer Setup
- [ ] Create app at https://developers.facebook.com
- [ ] Add Facebook Login product
- [ ] Configure Valid OAuth Redirect URIs
- [ ] Set up App Review for email permission
- [ ] Add domains to App Domains

### 3. Security Settings
```python
# settings.py - Production only
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
```

### 4. Rate Limiting
```python
# views.py'ye eklenecek
from django_ratelimit.decorators import ratelimit

@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='post')
class GoogleSocialLoginAPIView(APIView):
    # existing code...
```

## Advanced Features (Opsiyonel)

### 1. Social Account Linking
```python
# serializers.py'ye eklenecek
class SocialAccountLinkSerializer(serializers.Serializer):
    provider = serializers.ChoiceField(choices=['google', 'facebook', 'apple'])
    access_token = serializers.CharField()
    
    def link_account(self, user):
        # Mevcut user'a yeni social account bağla
        pass
```

### 2. Social Friends Import
```python
# Google Contacts API entegrasyonu
def import_google_contacts(user, access_token):
    # Google Contacts API'den arkadaş listesi al
    pass
```

### 3. Enhanced Logging
```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'social_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/social_auth.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'social_auth': {
            'handlers': ['social_file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
}

# views.py'de kullanım
import logging
social_logger = logging.getLogger('social_auth')

class GoogleSocialLoginAPIView(APIView):
    def post(self, request):
        social_logger.info(f"Google login attempt from IP: {request.META.get('REMOTE_ADDR')}")
        # existing code...
```

## Error Handling ve Monitoring

### 1. Custom Exception Handler
```python
# exceptions.py
class SocialAuthException(Exception):
    pass

class InvalidSocialTokenException(SocialAuthException):
    pass

class SocialProviderException(SocialAuthException):
    pass

# views.py'de kullanım
try:
    user = serializer.save()
except InvalidSocialTokenException:
    return Response({'error': 'Invalid social token'}, status=400)
except SocialProviderException as e:
    return Response({'error': str(e)}, status=500)
```

### 2. Health Check Endpoint
```python
# views.py
class SocialAuthHealthCheckView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Social auth services health check"""
        results = {}
        
        # Test Google API
        try:
            response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', timeout=5)
            results['google'] = 'ok' if response.status_code == 401 else 'error'
        except:
            results['google'] = 'error'
        
        # Test Facebook API
        try:
            response = requests.get('https://graph.facebook.com/me', timeout=5)
            results['facebook'] = 'ok' if response.status_code == 400 else 'error'
        except:
            results['facebook'] = 'error'
        
        return Response(results)
```

## Performance Optimizations

### 1. Caching Social Provider Keys
```python
# utils.py
from django.core.cache import cache
import requests

def get_google_keys():
    """Cache Google public keys for JWT verification"""
    cache_key = 'google_oauth_keys'
    keys = cache.get(cache_key)
    
    if not keys:
        response = requests.get('https://www.googleapis.com/oauth2/v3/certs')
        if response.status_code == 200:
            keys = response.json()
            cache.set(cache_key, keys, 3600)  # Cache for 1 hour
    
    return keys
```

### 2. Async Avatar Download
```python
# tasks.py (Celery task)
from celery import shared_task

@shared_task
def download_social_avatar(user_id, picture_url, provider):
    """Async avatar download task"""
    try:
        user = User.objects.get(id=user_id)
        # Download and save avatar logic here
    except Exception as e:
        logger.error(f"Avatar download failed for user {user_id}: {e}")

# serializers.py'de kullanım
# Sync yerine async download
from .tasks import download_social_avatar

def get_or_create_user(self, google_user_data):
    # ... user creation logic ...
    
    # Async avatar download
    picture_url = google_user_data.get('picture')
    if picture_url:
        download_social_avatar.delay(user.id, picture_url, 'google')
```

## Testing Suite

### 1. Unit Tests
```python
# tests/test_social_auth.py
from django.test import TestCase
from unittest.mock import patch, Mock
from accounts.api.serializers import GoogleSocialLoginSerializer

class GoogleSocialLoginTest(TestCase):
    
    @patch('requests.get')
    def test_valid_google_token(self, mock_get):
        """Test valid Google token processing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'email': 'test@gmail.com',
            'given_name': 'Test',
            'family_name': 'User',
            'picture': 'https://example.com/photo.jpg'
        }
        mock_get.return_value = mock_response
        
        serializer = GoogleSocialLoginSerializer(data={
            'access_token': 'valid_token_123'
        })
        
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.email, 'test@gmail.com')
        self.assertTrue(user.is_verified)
    
    @patch('requests.get')
    def test_invalid_google_token(self, mock_get):
        """Test invalid Google token handling"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        serializer = GoogleSocialLoginSerializer(data={
            'access_token': 'invalid_token'
        })
        
        self.assertFalse(serializer.is_valid())
```

### 2. Integration Tests
```python
# tests/test_social_integration.py
from django.test import TransactionTestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

User = get_user_model()

class SocialIntegrationTest(TransactionTestCase):
    
    def setUp(self):
        self.client = APIClient()
    
    def test_google_login_flow(self):
        """Test complete Google login flow"""
        # Mock Google token validation
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'email': 'integration@test.com',
                'given_name': 'Integration',
                'family_name': 'Test'
            }
            mock_get.return_value = mock_response
            
            # Test login
            response = self.client.post('/api/accounts/auth/social/google/', {
                'access_token': 'test_token'
            })
            
            self.assertEqual(response.status_code, 200)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)
            
            # Verify user created
            user = User.objects.get(email='integration@test.com')
            self.assertEqual(user.first_name, 'Integration')
            self.assertTrue(user.is_verified)
```

## Monitoring ve Analytics

### 1. Social Login Analytics
```python
# models.py
class SocialLoginEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.CharField(max_length=20)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    success = models.BooleanField()
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['provider', 'created_at']),
            models.Index(fields=['success', 'created_at']),
        ]

# views.py'de kullanım
def post(self, request):
    try:
        user = serializer.save()
        # Log successful login
        SocialLoginEvent.objects.create(
            user=user,
            provider='google',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            success=True
        )
    except Exception as e:
        # Log failed login
        SocialLoginEvent.objects.create(
            provider='google',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            success=False,
            error_message=str(e)
        )
```

### 2. Dashboard Metrics
```python
# management/commands/social_stats.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Generate social login statistics'
    
    def handle(self, *args, **options):
        last_30_days = timezone.now() - timedelta(days=30)
        
        # Provider statistics
        from accounts.models import SocialLoginEvent
        stats = SocialLoginEvent.objects.filter(
            created_at__gte=last_30_days
        ).values('provider').annotate(
            total=Count('id'),
            successful=Count('id', filter=Q(success=True))
        )
        
        for stat in stats:
            self.stdout.write(
                f"{stat['provider']}: {stat['successful']}/{stat['total']} "
                f"({stat['successful']/stat['total']*100:.1f}% success)"
            )
```

## Son Kontrol Listesi

### ✅ **Mevcut Durumunuz:**
1. ✅ Backend API endpoints (Google, Facebook, Apple)
2. ✅ JWT token entegrasyonu
3. ✅ User creation/update logic
4. ✅ Basic error handling
5. ✅ Settings configuration
6. ✅ Test script

### 🔧 **Hemen Eklenebilecekler:**
1. ⚠️ Frontend integration examples (yukarıda sağlandı)
2. ⚠️ Rate limiting
3. ⚠️ Enhanced logging
4. ⚠️ Health check endpoints
5. ⚠️ Unit tests

### 🚀 **Production için Gerekli:**
1. ❌ SSL certificates
2. ❌ Domain verification
3. ❌ Social provider app approval
4. ❌ Error monitoring (Sentry)
5. ❌ Performance monitoring

### 📊 **Gelişmiş Özellikler:**
1. ❌ Social account linking
2. ❌ Analytics dashboard
3. ❌ A/B testing
4. ❌ Social friends import
5. ❌ Account merge functionality

## Sonuç

Django boilerplate projenizde **social login implementasyonu %80 tamamlanmış** durumda! 

**Eksik olan sadece:**
- Frontend entegrasyon kodları (yukarıda sağlandı)
- Production deployment ayarları
- Bazı güvenlik ve monitoring iyileştirmeleri

**Bir sonraki adımlar:**
1. Frontend kodlarını projenize entegre edin
2. Google/Facebook developer console'da app'ları oluşturun
3. Environment variables'ları ayarlayın
4. Test edin ve production'a deploy edin

Genel olarak çok sağlam bir social login sisteminiz var! 🎉