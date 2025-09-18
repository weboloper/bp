from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model
from core.email_service import EmailService
from .serializers import (
    CustomTokenObtainPairSerializer, 
    UserRegistrationSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationResendSerializer
)

User = get_user_model()


class RegisterAPIView(APIView):
    """
    User registration endpoint
    accounts/views.py register_view'e benzer mantık
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Register new user
        """
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Create user
                user = serializer.save()
                
                # Generate email verification token - register_view ile aynı
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create verification link
                verification_link = f"{settings.FRONTEND_URL}/accounts/email-verify/{uid}/{token}/"
                
                # Send verification email
                try:
                    EmailService.send_critical_email(
                        template_name='accounts/emails/email_verification',
                        context={
                            'user': user,
                            'verification_link': verification_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        subject='Email Doğrulama - BP Django App',
                        recipient_list=[user.email]
                    )
                    
                    return Response({
                        'message': 'Kayıt başarılı! Email adresinize doğrulama linki gönderildi.',
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                        },
                        'email_sent': True
                    }, status=status.HTTP_201_CREATED)
                    
                except Exception as e:
                    print(f"Email verification email failed: {e}")
                    return Response({
                        'message': 'Kayıt başarılı ama email gönderiminde sorun oluştu.',
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                        },
                        'email_sent': False,
                        'warning': 'Email gönderimi başarısız. Giriş yapmayı deneyin.'
                    }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                return Response({
                    'error': 'Kayıt sırasında bir hata oluştu',
                    'detail': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Return validation errors
        return Response({
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetAPIView(APIView):
    """
    Password reset request endpoint
    accounts/views.py password_reset_view'e benzer mantık
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Send password reset email
        """
        serializer = PasswordResetSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.get_user()
            
            if user:
                # Generate reset token - password_reset_view ile aynı
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create reset link
                reset_link = f"{settings.FRONTEND_URL}/accounts/password-reset-confirm/{uid}/{token}/"
                
                # Send password reset email
                try:
                    EmailService.send_critical_email(
                        template_name='accounts/emails/password_reset',
                        context={
                            'user': user,
                            'reset_link': reset_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        subject='Şifre Sıfırlama Talebi - BP Django App',
                        recipient_list=[user.email]
                    )
                    
                    return Response({
                        'message': 'Şifre sıfırlama linki email adresinize gönderildi.'
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    print(f"Password reset email failed: {e}")
                    return Response({
                        'error': 'Email gönderimi başarısız. Lütfen tekrar deneyin.',
                        'detail': str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Security: Don't reveal if email exists - password_reset_view ile aynı
                return Response({
                    'message': 'Şifre sıfırlama linki email adresinize gönderildi.'
                }, status=status.HTTP_200_OK)
        
        # Return validation errors
        return Response({
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmAPIView(APIView):
    """
    Password reset confirm endpoint
    accounts/views.py password_reset_confirm_view'e benzer mantık
    """
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        """
        Reset password with token
        """
        try:
            # Decode user ID - password_reset_confirm_view ile aynı
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({
                'error': 'Geçersiz sıfırlama linki',
                'valid_link': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token):
            # Token valid, process password reset
            serializer = PasswordResetConfirmSerializer(data=request.data, user=user)
            
            if serializer.is_valid():
                try:
                    serializer.save()
                    return Response({
                        'message': 'Şifreniz başarıyla değiştirildi. Yeni şifrenizle giriş yapabilirsiniz.',
                        'valid_link': True
                    }, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({
                        'error': 'Şifre değiştirme sırasında hata oluştu',
                        'detail': str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Validation errors
            return Response({
                'error': 'Validation failed',
                'errors': serializer.errors,
                'valid_link': True
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Invalid token
            return Response({
                'error': 'Sıfırlama linki geçersiz veya süresi dolmuş',
                'valid_link': False
            }, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationResendAPIView(APIView):
    """
    Email verification resend endpoint
    accounts/views.py email_verification_resend_view'e benzer mantık
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Resend email verification link
        """
        serializer = EmailVerificationResendSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.get_user()
            
            if user:
                if user.is_verified:
                    return Response({
                        'message': 'Bu email adresi zaten doğrulanmış.',
                        'already_verified': True
                    }, status=status.HTTP_200_OK)
                
                # Generate verification token - email_verification_resend_view ile aynı
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create verification link
                verification_link = f"{settings.FRONTEND_URL}/accounts/email-verify/{uid}/{token}/"
                
                # Send verification email
                try:
                    EmailService.send_critical_email(
                        template_name='accounts/emails/email_verification',
                        context={
                            'user': user,
                            'verification_link': verification_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        subject='Email Doğrulama - BP Django App',
                        recipient_list=[user.email]
                    )
                    
                    return Response({
                        'message': 'Email doğrulama linki gönderildi.'
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    print(f"Email verification resend failed: {e}")
                    return Response({
                        'error': 'Email gönderimi başarısız. Lütfen tekrar deneyin.',
                        'detail': str(e)
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Security: Don't reveal if email exists - email_verification_resend_view ile aynı
                return Response({
                    'message': 'Email doğrulama linki gönderildi.'
                }, status=status.HTTP_200_OK)
        
        # Return validation errors
        return Response({
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationConfirmAPIView(APIView):
    """
    Email verification confirm endpoint
    accounts/views.py email_verification_confirm_view'e benzer mantık
    """
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        """
        Confirm email verification with token
        """
        try:
            # Decode user ID - email_verification_confirm_view ile aynı
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({
                'error': 'Geçersiz doğrulama linki',
                'valid_link': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token):
            # Verify user - email_verification_confirm_view ile aynı
            if not user.is_verified:
                user.is_verified = True
                user.save()
                
                # Send welcome email after verification
                try:
                    EmailService.send_smart_email(
                        template_name='accounts/emails/welcome',
                        context={
                            'user': user,
                            'site_url': settings.FRONTEND_URL,
                        },
                        subject='Hoş geldiniz! - BP Django App',
                        recipient_list=[user.email]
                    )
                except Exception as e:
                    print(f"Welcome email failed: {e}")
                
                return Response({
                    'message': f'Email adresiniz doğrulandı! Hoş geldin {user.username}!',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'is_verified': True
                    },
                    'valid_link': True,
                    'already_verified': False
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Email adresiniz zaten doğrulanmış.',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'is_verified': True
                    },
                    'valid_link': True,
                    'already_verified': True
                }, status=status.HTTP_200_OK)
        else:
            # Invalid token
            return Response({
                'error': 'Doğrulama linki geçersiz veya süresi dolmuş',
                'valid_link': False
            }, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom login view that accepts both username and email
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def get_serializer_context(self):
        """Add request to serializer context"""
        context = super().get_serializer_context()
        context['request'] = self.request
        return context


class MeAPIView(APIView):
    """
    Current user profile endpoint
    Requires JWT authentication
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get current user profile
        """
        user = request.user
        
        # Get or create profile if it doesn't exist
        profile_data = None
        if hasattr(user, 'profile'):
            profile = user.profile
            profile_data = {
                'birth_date': profile.birth_date,
                'bio': profile.bio,
                'avatar': profile.avatar.url if profile.avatar else None,
                'created_at': profile.created_at,
                'updated_at': profile.updated_at,
            }
        
        data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'date_joined': user.date_joined,
            'last_login': user.last_login,
            'profile': profile_data
        }
        
        return Response(data, status=status.HTTP_200_OK)
