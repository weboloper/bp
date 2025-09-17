from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

User = get_user_model()


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
        
        # Add user info to response (optional)
        if hasattr(refresh, 'access_token'):
            data.update({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_verified': user.is_verified,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                }
            })
        
        return data
