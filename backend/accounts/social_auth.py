"""
Social Authentication Base Classes

Bu modül tüm social authentication provider'lar için base class'ları içerir.
Her provider (Google, Facebook, vb.) bu base class'ı extend eder.
"""

import requests
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from accounts.models import Profile

User = get_user_model()


class BaseSocialAuth:
    """
    Base class for all social authentication providers
    
    Her social provider bu class'ı inherit eder ve kendi specific
    method'larını implement eder.
    
    Attributes:
        provider_name (str): Provider ismi (örn: 'google', 'facebook')
        user_info_url (str): User bilgilerini almak için API endpoint
    """
    
    provider_name = None  # Subclass'lar override etmeli
    user_info_url = None  # Subclass'lar override etmeli
    
    def __init__(self):
        if not self.provider_name:
            raise NotImplementedError("provider_name tanımlanmalı")
    
    def verify_token(self, access_token):
        """
        Access token'ın geçerliliğini kontrol et
        
        Args:
            access_token (str): Provider'dan alınan access token
            
        Returns:
            bool: Token geçerli ise True, değilse False
            
        Raises:
            NotImplementedError: Subclass implement etmeli
        """
        raise NotImplementedError("verify_token method'u implement edilmeli")
    
    def get_user_info(self, access_token):
        """
        Access token ile kullanıcı bilgilerini al
        
        Args:
            access_token (str): Provider'dan alınan access token
            
        Returns:
            dict: Provider'dan dönen raw user data
            
        Raises:
            NotImplementedError: Subclass implement etmeli
        """
        raise NotImplementedError("get_user_info method'u implement edilmeli")
    
    def extract_user_data(self, raw_data):
        """
        Provider'dan gelen raw data'yı standart formata çevir
        
        Args:
            raw_data (dict): Provider'dan gelen raw data
            
        Returns:
            dict: Standartlaştırılmış user data
                {
                    'email': str,
                    'first_name': str,
                    'last_name': str,
                }
        """
        # Default implementation - subclass override edebilir
        return {
            'email': raw_data.get('email'),
            'first_name': raw_data.get('given_name', raw_data.get('first_name', '')),
            'last_name': raw_data.get('family_name', raw_data.get('last_name', '')),
        }
    
    def generate_unique_username(self, email):
        """
        Email'den unique username oluştur
        
        Args:
            email (str): User email
            
        Returns:
            str: Unique username
        """
        username_base = email.split('@')[0]
        
        # Geçersiz karakterleri temizle
        username_base = ''.join(c for c in username_base if c.isalnum() or c in ('_', '-'))
        
        # Çok kısa ise 'user' ekle
        if len(username_base) < 3:
            username_base = f"user_{username_base}"
        
        username = username_base
        counter = 1
        
        # Unique username bulana kadar dene
        while User.objects.filter(username=username).exists():
            username = f"{username_base}{counter}"
            counter += 1
        
        return username
    
    def get_or_create_user(self, user_data):
        """
        User data ile kullanıcı oluştur veya mevcut kullanıcıyı getir
        
        Args:
            user_data (dict): Standartlaştırılmış user data
            
        Returns:
            User: Django User instance
            
        Raises:
            ValidationError: Email yoksa veya geçersizse
        """
        email = user_data.get('email')
        
        if not email:
            raise ValidationError(f'{self.provider_name} hesabından email bilgisi alınamadı')
        
        try:
            # Mevcut kullanıcı var mı?
            user = User.objects.get(email__iexact=email)
            
            # Kullanıcı bilgilerini güncelle (eğer boş ise)
            updated = False
            
            if not user.first_name and user_data.get('first_name'):
                user.first_name = user_data['first_name']
                updated = True
            
            if not user.last_name and user_data.get('last_name'):
                user.last_name = user_data['last_name']
                updated = True
            
            # Social login ile gelen kullanıcı doğrulanmış sayılır
            if not user.is_verified:
                user.is_verified = True
                updated = True
            
            if updated:
                user.save()
            
            return user
            
        except User.DoesNotExist:
            # Yeni kullanıcı oluştur
            username = self.generate_unique_username(email)
            
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', ''),
                is_verified=True  # Social login ile verified
            )
            
            # Profil oluştur
            self.create_profile(user)
            
            return user
    
    def create_profile(self, user):
        """
        Yeni kullanıcı için profile oluştur
        
        Args:
            user (User): Django User instance
        """
        try:
            Profile.objects.create(
                user=user,
                bio=f'{self.provider_name.capitalize()} ile katıldı'
            )
        except Exception as e:
            # Profile oluşturulamasa bile kullanıcı oluşturma devam etsin
            print(f"{self.provider_name} - Profile oluşturma hatası: {e}")
    
    def authenticate(self, access_token):
        """
        Main authentication flow
        
        Bu method tüm authentication akışını yönetir:
        1. Token'ı verify et
        2. User bilgilerini al
        3. Data'yı standart formata çevir
        4. User oluştur veya getir
        
        Args:
            access_token (str): Provider'dan alınan access token
            
        Returns:
            User: Authenticate edilmiş Django User instance
            
        Raises:
            ValidationError: Authentication başarısız ise
        """
        # 1. Token'ı verify et
        if not self.verify_token(access_token):
            raise ValidationError(f'Geçersiz {self.provider_name} access token')
        
        # 2. User bilgilerini al
        try:
            raw_data = self.get_user_info(access_token)
        except Exception as e:
            raise ValidationError(f'{self.provider_name} kullanıcı bilgileri alınamadı: {str(e)}')
        
        # 3. Data'yı standart formata çevir
        user_data = self.extract_user_data(raw_data)
        
        # 4. User oluştur veya getir
        user = self.get_or_create_user(user_data)
        
        return user


class GoogleAuth(BaseSocialAuth):
    """
    Google OAuth authentication implementation
    
    Google OAuth 2.0 kullanarak kullanıcı authentication'ı yapar.
    """
    
    provider_name = 'google'
    user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
    
    def verify_token(self, access_token):
        """
        Google access token'ı verify et
        
        Args:
            access_token (str): Google'dan alınan access token
            
        Returns:
            bool: Token geçerli ise True
        """
        try:
            response = requests.get(
                self.user_info_url,
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def get_user_info(self, access_token):
        """
        Google access token ile kullanıcı bilgilerini al
        
        Args:
            access_token (str): Google'dan alınan access token
            
        Returns:
            dict: Google'dan dönen user data
            
        Raises:
            requests.RequestException: API isteği başarısız ise
        """
        response = requests.get(
            self.user_info_url,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if response.status_code != 200:
            raise ValidationError('Google kullanıcı bilgileri alınamadı')
        
        return response.json()
    
    # extract_user_data parent class'dan inherit ediliyor
    # Google'un response formatı zaten uyumlu:
    # {
    #     "email": "user@gmail.com",
    #     "given_name": "John",
    #     "family_name": "Doe",
    #     "picture": "https://...",
    #     ...
    # }


class FacebookAuth(BaseSocialAuth):
    """
    Facebook OAuth authentication implementation
    
    Facebook Graph API kullanarak kullanıcı authentication'ı yapar.
    """
    
    provider_name = 'facebook'
    user_info_url = 'https://graph.facebook.com/me'
    
    def verify_token(self, access_token):
        """
        Facebook access token'ı verify et
        
        Args:
            access_token (str): Facebook'dan alınan access token
            
        Returns:
            bool: Token geçerli ise True
        """
        try:
            response = requests.get(
                self.user_info_url,
                params={'access_token': access_token, 'fields': 'id'},
                timeout=10
            )
            data = response.json()
            return response.status_code == 200 and 'id' in data
        except requests.RequestException:
            return False
    
    def get_user_info(self, access_token):
        """
        Facebook access token ile kullanıcı bilgilerini al
        
        Args:
            access_token (str): Facebook'dan alınan access token
            
        Returns:
            dict: Facebook'dan dönen user data
            
        Raises:
            requests.RequestException: API isteği başarısız ise
        """
        response = requests.get(
            self.user_info_url,
            params={
                'access_token': access_token,
                'fields': 'id,email,first_name,last_name,picture'
            },
            timeout=10
        )
        
        if response.status_code != 200:
            raise ValidationError('Facebook kullanıcı bilgileri alınamadı')
        
        data = response.json()
        
        # Error check
        if 'error' in data:
            raise ValidationError(f"Facebook API hatası: {data['error'].get('message', 'Unknown error')}")
        
        return data
    
    def extract_user_data(self, raw_data):
        """
        Facebook'un response formatı biraz farklı, override ediyoruz
        
        Facebook response:
        {
            "id": "123456789",
            "email": "user@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "picture": {...}
        }
        """
        return {
            'email': raw_data.get('email'),
            'first_name': raw_data.get('first_name', ''),
            'last_name': raw_data.get('last_name', ''),
        }


class AppleAuth(BaseSocialAuth):
    """
    Apple Sign In authentication implementation
    
    Apple OAuth 2.0 kullanarak kullanıcı authentication'ı yapar.
    Apple id_token (JWT) kullanır.
    
    NOT: Bu basit implementation JWT token'ı verify etmez.
    Production için Apple public key ile signature verification eklenmelidir.
    """
    
    provider_name = 'apple'
    
    def verify_token(self, id_token):
        """
        Apple id_token'ı verify et (basit decode)
        
        NOT: Bu sadece format kontrolü yapar, imza doğrulaması yapmaz!
        Production için PyJWT ile tam verification gerekli.
        
        Args:
            id_token (str): Apple'dan alınan JWT id_token
            
        Returns:
            bool: Token formatı geçerli ise True
        """
        try:
            # JWT format kontrolü: 3 parça olmalı (header.payload.signature)
            parts = id_token.split('.')
            if len(parts) != 3:
                return False
            
            # Payload decode edilebilir mi?
            import base64
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            base64.urlsafe_b64decode(payload)
            
            return True
        except Exception:
            return False
    
    def get_user_info(self, id_token):
        """
        Apple id_token'dan kullanıcı bilgilerini çıkar
        
        Apple Sign In'de user bilgileri JWT token içinde gelir.
        Ayrı bir API isteği gerekmez.
        
        Args:
            id_token (str): Apple'dan alınan JWT id_token
            
        Returns:
            dict: Token içinden decode edilmiş user data
            
        Raises:
            ValidationError: Token decode edilemezse
        """
        try:
            import json
            import base64
            
            # JWT token'ın payload kısmını decode et
            parts = id_token.split('.')
            if len(parts) != 3:
                raise ValidationError('Geçersiz Apple token formatı')
            
            # Base64 decode
            payload = parts[1]
            # Padding ekle (base64 için gerekli)
            payload += '=' * (4 - len(payload) % 4)
            decoded_payload = base64.urlsafe_b64decode(payload)
            
            # JSON parse
            user_data = json.loads(decoded_payload)
            
            return user_data
            
        except Exception as e:
            raise ValidationError(f'Apple token decode edilemedi: {str(e)}')
    
    def extract_user_data(self, raw_data):
        """
        Apple'dan gelen raw data'yı standart formata çevir
        
        Apple JWT token payload formatı:
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.yourapp.service",
            "exp": 1234567890,
            "iat": 1234567890,
            "sub": "001234.abcd...",
            "email": "user@privaterelay.appleid.com",
            "email_verified": true,
            ...
        }
        
        NOT: Apple ilk login'de ayrıca 'user' JSON'u gönderir (name için).
        Ama o bilgi burada değil, callback view'da handle edilir.
        """
        return {
            'email': raw_data.get('email'),
            'first_name': '',  # Apple token içinde isim yok
            'last_name': '',   # Ayrı 'user' JSON'unda gelir (ilk login)
        }


# Helper function - view'larda kullanmak için
def get_social_auth_provider(provider_name):
    """
    Provider ismine göre authentication class'ı döndür
    
    Args:
        provider_name (str): 'google', 'facebook', 'apple'
        
    Returns:
        BaseSocialAuth: Authentication class instance
        
    Raises:
        ValueError: Geçersiz provider ismi
        
    Usage:
        auth_provider = get_social_auth_provider('google')
        user = auth_provider.authenticate(access_token)
    """
    providers = {
        'google': GoogleAuth,
        'facebook': FacebookAuth,
        'apple': AppleAuth,
    }
    
    provider_class = providers.get(provider_name.lower())
    
    if not provider_class:
        raise ValueError(
            f"Geçersiz provider: {provider_name}. "
            f"Geçerli provider'lar: {', '.join(providers.keys())}"
        )
    
    return provider_class()
