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
    EmailVerificationResendSerializer,
    PasswordChangeSerializer,
    EmailChangeSerializer,
    ProfileUpdateSerializer,
    UsernameChangeSerializer
)

User = get_user_model()


class RegisterAPIView(APIView):
    """
    User registration endpoint
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
                
                # Generate email verification token
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
                except Exception as e:
                    print(f"Email verification email failed: {e}")
                
                # Return user data - DRF default success format
                return Response({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                # Server error - DRF default format
                return Response(
                    {'detail': 'Kayıt sırasında bir hata oluştu'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsernameChangeAPIView(APIView):
    """
    Username change endpoint for authenticated users
    accounts/views.py username_change_view'e benzer mantık
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Change username with current password verification
        """
        serializer = UsernameChangeSerializer(data=request.data, user=request.user)
        
        if serializer.is_valid():
            try:
                old_username = request.user.username
                
                # Save new username
                user = serializer.save()
                
                return Response({
                    'detail': f'Kullanıcı adınız başarıyla "{old_username}" adresinden "{user.username}" olarak değiştirildi.',
                    'old_username': old_username,
                    'new_username': user.username
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                return Response(
                    {'detail': 'Kullanıcı adı değiştirme sırasında hata oluştu'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetAPIView(APIView):
    """
    Password reset request endpoint
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
                # Generate reset token
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
                except Exception as e:
                    print(f"Password reset email failed: {e}")
                    return Response(
                        {'detail': 'Email gönderimi başarısız'}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Always return success (security) - DRF default format
            return Response(
                {'detail': 'Şifre sıfırlama linki email adresinize gönderildi.'}, 
                status=status.HTTP_200_OK
            )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmAPIView(APIView):
    """
    Password reset confirm endpoint
    """
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        """
        Reset password with token
        """
        try:
            # Decode user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'detail': 'Geçersiz sıfırlama linki'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token):
            # Token valid, process password reset
            serializer = PasswordResetConfirmSerializer(data=request.data, user=user)
            
            if serializer.is_valid():
                try:
                    serializer.save()
                    return Response(
                        {'detail': 'Şifreniz başarıyla değiştirildi'}, 
                        status=status.HTTP_200_OK
                    )
                except Exception as e:
                    return Response(
                        {'detail': 'Şifre değiştirme sırasında hata oluştu'}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Return validation errors - DRF default format
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Invalid token
            return Response(
                {'detail': 'Sıfırlama linki geçersiz veya süresi dolmuş'}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class PasswordChangeAPIView(APIView):
    """
    Password change endpoint for authenticated users
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Change user password
        """
        serializer = PasswordChangeSerializer(data=request.data, user=request.user)
        
        if serializer.is_valid():
            try:
                # Save new password
                serializer.save()
                
                return Response(
                    {'detail': 'Şifreniz başarıyla değiştirildi'}, 
                    status=status.HTTP_200_OK
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Şifre değiştirme sırasında hata oluştu'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeAPIView(APIView):
    """
    Email change request endpoint for authenticated users
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Request email change - sends confirmation to new email
        """
        serializer = EmailChangeSerializer(data=request.data, user=request.user)
        
        if serializer.is_valid():
            try:
                new_email = serializer.validated_data['new_email']
                
                # Generate email change token
                token = default_token_generator.make_token(request.user)
                uid = urlsafe_base64_encode(force_bytes(request.user.pk))
                
                # Create confirmation link
                confirmation_link = f"{settings.FRONTEND_URL}/accounts/email-change-confirm/{uid}/{token}/{urlsafe_base64_encode(force_bytes(new_email))}/"
                
                # Send confirmation email to NEW email address
                try:
                    EmailService.send_critical_email(
                        template_name='accounts/emails/email_change_confirmation',
                        context={
                            'user': request.user,
                            'old_email': request.user.email,
                            'new_email': new_email,
                            'confirmation_link': confirmation_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        subject='Email Değişikliği Onayı - BP Django App',
                        recipient_list=[new_email]
                    )
                    
                    return Response(
                        {'detail': f'Email değişiklik onayı {new_email} adresine gönderildi. Lütfen emailinizi kontrol edin.'}, 
                        status=status.HTTP_200_OK
                    )
                    
                except Exception as e:
                    print(f"Email change confirmation email failed: {e}")
                    return Response(
                        {'detail': 'Email gönderimi başarısız. Lütfen tekrar deneyin.'}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                
            except Exception as e:
                return Response(
                    {'detail': 'Email değişiklik talebi sırasında hata oluştu'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeConfirmAPIView(APIView):
    """
    Email change confirmation endpoint
    """
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token, new_email_b64):
        """
        Confirm email change with token
        """
        try:
            # Decode user ID and new email
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            new_email = force_str(urlsafe_base64_decode(new_email_b64))
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'detail': 'Geçersiz email değişiklik linki'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token) and new_email:
            # Check if new email is still available
            if User.objects.filter(email__iexact=new_email).exists():
                return Response(
                    {'detail': 'Bu email adresi artık kullanılıyor. Lütfen farklı bir email deneyin.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            old_email = user.email
            
            # Update user email
            user.email = new_email
            user.save()
            
            # Send notification to OLD email address
            try:
                from django.utils import timezone
                EmailService.send_critical_email(
                    template_name='accounts/emails/email_change_notification',
                    context={
                        'user': user,
                        'old_email': old_email,
                        'new_email': new_email,
                        'change_date': timezone.now(),
                        'site_url': settings.FRONTEND_URL,
                    },
                    subject='Email Adresi Değiştirildi - BP Django App',
                    recipient_list=[old_email]
                )
            except Exception as e:
                print(f"Email change notification failed: {e}")
            
            return Response({
                'detail': f'Email adresiniz başarıyla {new_email} olarak değiştirildi.',
                'old_email': old_email,
                'new_email': new_email
            }, status=status.HTTP_200_OK)
        else:
            # Invalid token
            return Response(
                {'detail': 'Email değişiklik linki geçersiz veya süresi dolmuş'}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailVerificationResendAPIView(APIView):
    """
    Email verification resend endpoint
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
                    return Response(
                        {'detail': 'Bu email adresi zaten doğrulanmış'}, 
                        status=status.HTTP_200_OK
                    )
                
                # Generate verification token
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
                except Exception as e:
                    print(f"Email verification resend failed: {e}")
                    return Response(
                        {'detail': 'Email gönderimi başarısız'}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Always return success (security) - DRF default format
            return Response(
                {'detail': 'Email doğrulama linki gönderildi'}, 
                status=status.HTTP_200_OK
            )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationConfirmAPIView(APIView):
    """
    Email verification confirm endpoint
    """
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        """
        Confirm email verification with token
        """
        try:
            # Decode user ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {'detail': 'Geçersiz doğrulama linki'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token):
            # Verify user
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
                
                return Response(
                    {'detail': f'Email adresiniz doğrulandı! Hoş geldin {user.username}!'}, 
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'detail': 'Email adresiniz zaten doğrulanmış'}, 
                    status=status.HTTP_200_OK
                )
        else:
            # Invalid token
            return Response(
                {'detail': 'Doğrulama linki geçersiz veya süresi dolmuş'}, 
                status=status.HTTP_400_BAD_REQUEST
            )


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
    Current user profile endpoint - RESTful design
    GET: Get current user profile
    PATCH: Update profile (first_name, last_name, bio, avatar, birth_date)
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
    
    def patch(self, request):
        """
        Update user profile (first_name, last_name, bio, avatar, birth_date)
        """
        serializer = ProfileUpdateSerializer(data=request.data, user=request.user)
        
        if serializer.is_valid():
            try:
                # Save updated profile
                user = serializer.save()
                
                # Return updated profile data
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
                
                return Response({
                    'detail': 'Profiliniz başarıyla güncellendi.',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'profile': profile_data
                    }
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                return Response(
                    {'detail': 'Profil güncellemesi sırasında hata oluştu'}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
