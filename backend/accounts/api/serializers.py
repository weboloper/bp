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


class UsernameChangeSerializer(serializers.Serializer):
    """
    Username change serializer - accounts/forms.py UsernameChangeForm'a benzer mantık
    """
    current_password = serializers.CharField(write_only=True, required=True)
    new_username = serializers.CharField(max_length=30, required=True)
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def validate_current_password(self, value):
        """
        Current password validation - form'daki clean_current_password ile aynı
        """
        current_password = value
        
        if not current_password:
            raise serializers.ValidationError('Mevcut şifrenizi girin')
        
        # Check if current password is correct
        if self.user and not self.user.check_password(current_password):
            raise serializers.ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def validate_new_username(self, value):
        """
        New username validation - form'daki clean_new_username ile aynı
        """
        new_username = value.strip()
        
        if not new_username:
            raise serializers.ValidationError('Yeni kullanıcı adı gerekli')
        
        if len(new_username) < 3:
            raise serializers.ValidationError('Kullanıcı adı en az 3 karakter olmalı')
        
        if len(new_username) > 30:
            raise serializers.ValidationError('Kullanıcı adı en fazla 30 karakter olabilir')
        
        # Check if same as current username
        if self.user and new_username.lower() == self.user.username.lower():
            raise serializers.ValidationError('Yeni kullanıcı adı mevcut kullanıcı adı ile aynı olamaz')
        
        # Alphanumeric validation
        try:
            validate_alphanumeric_username(new_username)
        except ValidationError as e:
            raise serializers.ValidationError(str(e.message))
        
        # Check if username exists
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if User.objects.filter(username__iexact=new_username).exists():
            raise serializers.ValidationError('Bu kullanıcı adı zaten alınmış')
        
        return new_username
    
    def save(self):
        """
        Kullanıcının username'ini güncelle - form'daki save ile aynı
        """
        if not self.user:
            raise serializers.ValidationError('User not provided')
        
        new_username = self.validated_data['new_username']
        self.user.username = new_username
        self.user.save()
        return self.user


class EmailChangeSerializer(serializers.Serializer):
    """
    Email change serializer - accounts/forms.py EmailChangeForm'a benzer mantık
    """
    current_password = serializers.CharField(write_only=True, required=True)
    new_email = serializers.EmailField(required=True)
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def validate_current_password(self, value):
        """
        Current password validation - form'daki clean_current_password ile aynı
        """
        current_password = value
        
        if not current_password:
            raise serializers.ValidationError('Mevcut şifrenizi girin')
        
        # Check if current password is correct
        if self.user and not self.user.check_password(current_password):
            raise serializers.ValidationError('Mevcut şifre yanlış')
        
        return current_password
    
    def validate_new_email(self, value):
        """
        New email validation - form'daki clean_new_email ile aynı
        """
        new_email = value.strip().lower()
        
        if not new_email:
            raise serializers.ValidationError('Yeni email adresi gerekli')
        
        # Check if same as current email
        if self.user and new_email == self.user.email.lower():
            raise serializers.ValidationError('Yeni email adresi mevcut email ile aynı olamaz')
        
        # Django's built-in email validation (already handled by EmailField)
        # But we do additional checks
        
        # Check if email already exists
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if User.objects.filter(email__iexact=new_email).exists():
            raise serializers.ValidationError('Bu email adresi zaten kullanılıyor')
        
        return new_email


class ProfileUpdateSerializer(serializers.Serializer):
    """
    Profile update serializer - accounts/forms.py ProfileUpdateForm + ProfileDetailsForm'a benzer mantık
    """
    # User fields
    first_name = serializers.CharField(max_length=30, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=30, required=False, allow_blank=True)
    
    # Profile fields
    bio = serializers.CharField(max_length=500, required=False, allow_blank=True)
    birth_date = serializers.DateField(required=False, allow_null=True)
    avatar = serializers.ImageField(required=False, allow_null=True)
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def validate_first_name(self, value):
        """
        First name validation - form'daki clean_first_name ile aynı
        """
        first_name = value.strip() if value else ''
        
        if len(first_name) > 30:
            raise serializers.ValidationError('Ad en fazla 30 karakter olabilir')
        
        return first_name
    
    def validate_last_name(self, value):
        """
        Last name validation - form'daki clean_last_name ile aynı
        """
        last_name = value.strip() if value else ''
        
        if len(last_name) > 30:
            raise serializers.ValidationError('Soyad en fazla 30 karakter olabilir')
        
        return last_name
    
    def validate_bio(self, value):
        """
        Bio validation - form'daki clean_bio ile aynı
        """
        bio = value.strip() if value else ''
        
        if len(bio) > 500:
            raise serializers.ValidationError('Bio en fazla 500 karakter olabilir')
        
        return bio
    
    def save(self):
        """
        Update user and profile - form'daki save ile aynı mantık
        """
        if not self.user:
            raise serializers.ValidationError('User not provided')
        
        # Update user fields
        self.user.first_name = self.validated_data.get('first_name', self.user.first_name)
        self.user.last_name = self.validated_data.get('last_name', self.user.last_name)
        self.user.save()
        
        # Get or create profile
        from accounts.models import Profile
        try:
            profile = self.user.profile
        except Profile.DoesNotExist:
            profile = Profile.objects.create(
                user=self.user,
                birth_date=None,
                bio='',
                avatar=None
            )
        
        # Update profile fields
        if 'bio' in self.validated_data:
            profile.bio = self.validated_data['bio']
        if 'birth_date' in self.validated_data:
            profile.birth_date = self.validated_data['birth_date']
        if 'avatar' in self.validated_data:
            profile.avatar = self.validated_data['avatar']
        
        profile.save()
        
        return self.user


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Password reset confirm serializer - accounts/forms.py PasswordResetConfirmForm'a benzer mantık
    """
    password1 = serializers.CharField(write_only=True, min_length=1)
    password2 = serializers.CharField(write_only=True, min_length=1)
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def validate_password1(self, value):
        """
        Password validation - form'daki clean_password1 ile aynı
        """
        password1 = value
        
        if not password1:
            raise serializers.ValidationError('Yeni şifre gerekli')
        
        # Django's built-in password validation with user context
        if self.user:
            try:
                validate_password(password1, self.user)
            except ValidationError as e:
                raise serializers.ValidationError(' '.join(e.messages))
        
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
        
        if password1 and password2:
            if password1 != password2:
                raise serializers.ValidationError({
                    'password2': 'Şifreler eşleşmiyor'
                })
        
        return attrs
    
    def save(self):
        """
        Kullanıcının şifresini güncelle - form'daki save ile aynı
        """
        if not self.user:
            raise serializers.ValidationError('User not provided')
        
        password = self.validated_data['password1']
        self.user.set_password(password)
        self.user.save()
        return self.user


class EmailVerificationResendSerializer(serializers.Serializer):
    """
    Email verification resend serializer - accounts/forms.py EmailVerificationResendForm'a benzer mantık
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


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer that accepts both username and email
    """
    username_field = 'username'  # This will actually accept username OR email
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Update field help text to reflect that it accepts both
        self.fields['username'].help_text = 'Username veya email adresi giriniz'
    
    def validate(self, attrs):
        username_or_email = attrs.get('username')
        password = attrs.get('password')
        
        if not username_or_email or not password:
            raise serializers.ValidationError('Kullanıcı adı/email ve şifre gerekli')
        
        # Check if input is email or username
        user = None
        username_to_authenticate = username_or_email
        
        if '@' in username_or_email:
            # It's an email
            try:
                validate_email(username_or_email)
                # Find user by email
                try:
                    user_obj = User.objects.get(email__iexact=username_or_email)
                    username_to_authenticate = user_obj.username
                except User.DoesNotExist:
                    raise serializers.ValidationError(
                        'Bu email adresi ile kayıtlı kullanıcı bulunamadı'
                    )
            except ValidationError:
                raise serializers.ValidationError('Geçerli bir email adresi giriniz')
        
        # Authenticate user
        user = authenticate(
            request=self.context.get('request'),
            username=username_to_authenticate,
            password=password
        )
        
        if user is None:
            if '@' in username_or_email:
                raise serializers.ValidationError('Email veya şifre hatalı')
            else:
                raise serializers.ValidationError('Kullanıcı adı veya şifre hatalı')
        
        if not user.is_active:
            raise serializers.ValidationError('Hesabınız devre dışı bırakılmış')
        
        if not user.is_verified:
            raise serializers.ValidationError(
                'Hesabınız henüz doğrulanmamış. Email adresinizi kontrol edin.'
            )
        
        # If we get here, authentication was successful
        # Get the token data using the parent class logic
        refresh = self.get_token(user)
        
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        
        return data
