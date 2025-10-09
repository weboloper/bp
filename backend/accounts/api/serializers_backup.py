from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from accounts.utils import validate_alphanumeric_username

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    User registration serializer - accounts/forms.py UserRegistrationForm'a benzer mantık
    """
    password1 = serializers.CharField(write_only=True, min_length=1)
    password2 = serializers.CharField(write_only=True, min_length=1)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        
    def validate_username(self, value):
        """
        Username validation - form'daki clean_username ile aynı
        """
        username = value.strip()
        
        if not username:
            raise serializers.ValidationError('Kullanıcı adı gerekli')
        
        if len(username) < 3:
            raise serializers.ValidationError('Kullanıcı adı en az 3 karakter olmalı')
        
        if len(username) > 30:
            raise serializers.ValidationError('Kullanıcı adı en fazla 30 karakter olabilir')
        
        # Alphanumeric validation
        try:
            validate_alphanumeric_username(username)
        except ValidationError as e:
            raise serializers.ValidationError(str(e.message))
        
        # Check if username exists
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('Bu kullanıcı adı zaten alınmış')
        
        return username
    
    def validate_email(self, value):
        """
        Email validation - form'daki clean_email ile aynı
        """
        email = value.strip()
        
        if not email:
            raise serializers.ValidationError('Email gerekli')
        
        # Django's built-in email validation
        try:
            validate_email(email)
        except ValidationError:
            raise serializers.ValidationError('Geçerli bir email adresi giriniz')
        
        # Check if email exists
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Bu email adresi zaten kayıtlı')
        
        return email
    
    def validate_password1(self, value):
        """
        Password validation - form'daki clean_password1 ile aynı
        """
        password1 = value
        
        if not password1:
            raise serializers.ValidationError('Şifre gerekli')
        
        return password1
    
    def validate_password2(self, value):
        """
        Password confirmation validation
        """
        password2 = value
        
        if not password2:
            raise serializers.ValidationError('Şifre tekrarı gerekli')
        
        return password2
    
    def validate(self, attrs):
        """
        Cross-field validation - form'daki clean ile aynı
        """
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')
        username = attrs.get('username')
        email = attrs.get('email')
        
        if password1 and password2:
            if password1 != password2:
                raise serializers.ValidationError({
                    'password2': 'Şifreler eşleşmiyor'
                })
        
        # Django's password validation with user context
        if password1 and username and email:
            # Create temporary user for validation (not saved)
            temp_user = User(
                username=username,
                email=email
            )
            
            try:
                validate_password(password1, temp_user)
            except ValidationError as e:
                raise serializers.ValidationError({
                    'password1': ' '.join(e.messages)
                })
        
        return attrs
    
    def create(self, validated_data):
        """
        Create user - form'daki save ile aynı mantık
        """
        # Remove password2, we don't need it
        validated_data.pop('password2')
        password = validated_data.pop('password1')
        
        # Create user
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        
        return user


class PasswordResetSerializer(serializers.Serializer):
    """
    Password reset request serializer - accounts/forms.py PasswordResetForm'a benzer mantık
    """
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        """
        Email validation - form'daki clean_email ile aynı
        """
        email = value.strip()
        
        if not email:
            raise serializers.ValidationError('Email adresi gerekli')
        
        # Django's built-in email validation (already handled by EmailField)
        return email
    
    def get_user(self):
        """
        Email ile kullanıcıyı getir, yoksa None döndür - form'daki get_user ile aynı
        """
        email = self.validated_data.get('email')
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None


class PasswordChangeSerializer(serializers.Serializer):
    """
    Password change serializer - accounts/forms.py PasswordChangeForm'a benzer mantık
    """
    current_password = serializers.CharField(write_only=True, required=True)
    new_password1 = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def validate_current_password(self, value):
        """
        Current password validation - form'daki clean_current_password ile aynı
        """
        current_password = value
        
        if not current_password:
            raise serializers.ValidationError('Mevcut şifre gerekli')
        
        # Check if current password is correct
        if self.user and not self.user.check_password(current_password):
            raise serializers.ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def validate_new_password1(self, value):
        """
        New password validation - form'daki clean_new_password1 ile aynı
        """
        new_password1 = value
        
        if not new_password1:
            raise serializers.ValidationError('Yeni şifre gerekli')
        
        # Django's built-in password validation with user context
        if self.user:
            try:
                validate_password(new_password1, self.user)
            except ValidationError as e:
                raise serializers.ValidationError(' '.join(e.messages))
        
        return new_password1
    
    def validate_new_password2(self, value):
        """
        New password confirmation validation
        """
        new_password2 = value
        
        if not new_password2:
            raise serializers.ValidationError('Yeni şifre tekrarı gerekli')
        
        return new_password2
    
    def validate(self, attrs):
        """
        Cross-field validation - form'daki clean ile aynı
        """
        new_password1 = attrs.get('new_password1')
        new_password2 = attrs.get('new_password2')
        current_password = attrs.get('current_password')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise serializers.ValidationError({
                    'new_password2': 'Yeni şifreler eşleşmiyor'
                })
        
        if current_password and new_password1:
            if current_password == new_password1:
                raise serializers.ValidationError({
                    'new_password1': 'Yeni şifre mevcut şifre ile aynı olamaz'
                })
        
        return attrs
    
    def save(self):
        """
        Kullanıcının şifresini güncelle - form'daki save ile aynı
        """
        if not self.user:
            raise serializers.ValidationError('User not provided')
        
        new_password = self.validated_data['new_password1']
        self.user.set_password(new_password)
        self.user.save()
        return self.user


class GoogleSocialLoginSerializer(serializers.Serializer):
    """
    Google Social Login serializer
    Frontend'den gelen Google OAuth access token'ını verify eder ve User oluşturur/bulur
    """
    access_token = serializers.CharField(required=True)
    
    def validate_access_token(self, value):
        """
        Google access token'ını verify et
        """
        access_token = value.strip()
        
        if not access_token:
            raise serializers.ValidationError('Google access token gerekli')
        
        try:
            # Google OAuth2 API ile token verify et
            from google.oauth2 import id_token
            from google.auth.transport import requests
            import google.auth.transport.requests
            
            # Google userinfo API'ye request at
            import requests as req
            response = req.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            if response.status_code != 200:
                raise serializers.ValidationError('Geçersiz Google access token')
            
            user_data = response.json()
            
            # Required fields check
            if not user_data.get('email'):
                raise serializers.ValidationError('Google hesabından email bilgisi alınamadı')
            
            if not user_data.get('verified_email', False):
                raise serializers.ValidationError('Google email adresi doğrulanmamış')
            
            return {
                'access_token': access_token,
                'user_data': user_data
            }
            
        except Exception as e:
            raise serializers.ValidationError(f'Google token doğrulama hatası: {str(e)}')
    
    def save(self):
        """
        Google user data'sinden User oluştur veya bul
        """
        validated_data = self.validated_data['access_token']
        user_data = validated_data['user_data']
        
        email = user_data['email']
        google_id = user_data['id']
        first_name = user_data.get('given_name', '')
        last_name = user_data.get('family_name', '')
        picture = user_data.get('picture', '')
        
        # User'ı email ile bul veya oluştur
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            # Email ile mevcut user'ı bul
            user = User.objects.get(email__iexact=email)
            
            # Eğer user varsa, Google bilgilerini güncelle
            if not user.first_name and first_name:
                user.first_name = first_name
            if not user.last_name and last_name:
                user.last_name = last_name
            
            # User verified olarak işaretle (Google'dan geldiği için)
            if not user.is_verified:
                user.is_verified = True
                
            user.save()
            
        except User.DoesNotExist:
            # Yeni user oluştur
            # Username oluştur (email'in @ öncesi + unique suffix)
            base_username = email.split('@')[0]
            username = base_username
            
            # Username unique olana kadar suffix ekle
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_verified=True,  # Google'dan geldiği için verified
                is_active=True
            )
            
            # Profile oluştur
            from accounts.models import Profile
            try:
                profile = Profile.objects.create(
                    user=user,
                    bio=f'Google ile kayıt oldu',
                )
                
                # Avatar'ı Google'dan indirmeyi dene (opsiyonel)
                if picture:
                    try:
                        import requests as req
                        from django.core.files.base import ContentFile
                        from django.core.files.storage import default_storage
                        import uuid
                        
                        response = req.get(picture)
                        if response.status_code == 200:
                            file_name = f"avatars/google_{user.id}_{uuid.uuid4().hex[:8]}.jpg"
                            profile.avatar.save(
                                file_name,
                                ContentFile(response.content),
                                save=True
                            )
                    except Exception as e:
                        # Avatar indirme başarısız olursa devam et
                        print(f"Google avatar download failed: {e}")
                        
            except Exception as e:
                print(f"Profile creation failed: {e}")
        
        return user


# ... (diğer serializer'lar devam ediyor)
