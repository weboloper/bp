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
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django_ratelimit.decorators import ratelimit
from notifications.services import send_template_email

from .serializers import (
    CustomTokenObtainPairSerializer,
    UserRegistrationSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationResendSerializer,
    PasswordSetSerializer,
    PasswordChangeSerializer,
    EmailChangeSerializer,
    ProfileUpdateSerializer,
    UsernameChangeSerializer,
    GoogleSocialLoginSerializer,
    FacebookSocialLoginSerializer,
    AppleSocialLoginSerializer,
    MeSerializer,
    UserProfileSerializer,
    ProfileDetailSerializer
)

User = get_user_model()


@method_decorator(ratelimit(key='ip', rate='5/m', method='POST'), name='post')
class RegisterAPIView(APIView):
    """
    User registration endpoint
    Rate limited: 5 requests per minute per IP
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
                    send_template_email(
                        to=user.email,
                        subject='Email Doğrulama - BP Django App',
                        template_name='accounts/emails/email_verification',
                        context={
                            'user': user,
                            'verification_link': verification_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        sync=True
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
                    {'detail': _('An error occurred during registration')}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='post')
class GoogleSocialLoginAPIView(APIView):
    """
    Google Social Login API View
    Frontend'den Google access token alır, verify eder ve JWT token döner
    Rate limited: 10 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Google social login
        
        Request format:
        {
            "access_token": "google_oauth_access_token_from_frontend"
        }
        
        Response format:
        {
            "access": "jwt_access_token",
            "refresh": "jwt_refresh_token"
        }
        """
        serializer = GoogleSocialLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Google token verify et ve user oluştur/bul
                user = serializer.save()
                
                # JWT tokens oluştur - mevcut sistemle aynı
                from rest_framework_simplejwt.tokens import RefreshToken
                
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # Unexpected errors
                return Response(
                    {'detail': _('An error occurred during Google login: {}').format(str(e))}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='post')
class FacebookSocialLoginAPIView(APIView):
    """
    Facebook Social Login API View
    Frontend'den Facebook access token alır, verify eder ve JWT token döner
    Rate limited: 10 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Facebook social login
        
        Request format:
        {
            "access_token": "facebook_oauth_access_token_from_frontend"
        }
        
        Response format:
        {
            "access": "jwt_access_token",
            "refresh": "jwt_refresh_token"
        }
        """
        serializer = FacebookSocialLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Facebook token verify et ve user oluştur/bul
                user = serializer.save()
                
                # JWT tokens oluştur
                from rest_framework_simplejwt.tokens import RefreshToken
                
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # Unexpected errors
                return Response(
                    {'detail': _('An error occurred during Facebook login: {}').format(str(e))}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='10/m', method='POST'), name='post')
class AppleSocialLoginAPIView(APIView):
    """
    Apple Social Login API View
    Frontend'den Apple identity token alır, verify eder ve JWT token döner
    Rate limited: 10 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Apple social login
        
        Request format:
        {
            "identity_token": "apple_identity_token_from_frontend"
        }
        
        Response format:
        {
            "access": "jwt_access_token",
            "refresh": "jwt_refresh_token"
        }
        """
        serializer = AppleSocialLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                # Apple token verify et ve user oluştur/bul
                user = serializer.save()
                
                # JWT tokens oluştur
                from rest_framework_simplejwt.tokens import RefreshToken
                
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # Unexpected errors
                return Response(
                    {'detail': _('An error occurred during Apple login: {}').format(str(e))}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='user_or_ip', rate='5/h', method='POST'), name='post')
class UsernameChangeAPIView(APIView):
    """
    Username change endpoint for authenticated users
    Rate limited: 5 requests per hour per user or IP
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Change username with current password verification
        """
        # Check if user has a password
        if not request.user.has_usable_password():
            return Response(
                {'detail': _('You must create a password first to change your username. Use the password-set endpoint.')},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = UsernameChangeSerializer(data=request.data, user=request.user)
        
        if serializer.is_valid():
            try:
                old_username = request.user.username
                
                # Save new username
                user = serializer.save()
                
                return Response({
                    'detail': _('Your username has been successfully changed from "{}" to "{}".').format(old_username, user.username),
                    'old_username': old_username,
                    'new_username': user.username
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                return Response(
                    {'detail': _('An error occurred while changing username')}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='3/h', method='POST'), name='post')
class PasswordResetRequestAPIView(APIView):
    """
    Password reset request endpoint
    Rate limited: 3 requests per hour per IP (security)
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
                    send_template_email(
                        to=user.email,
                        subject='Şifre Sıfırlama Talebi - BP Django App',
                        template_name='accounts/emails/password_reset',
                        context={
                            'user': user,
                            'reset_link': reset_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        sync=True
                    )
                except Exception as e:
                    print(f"Password reset email failed: {e}")
                    return Response(
                        {'detail': _('Email sending failed')}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Always return success (security) - DRF default format
            return Response(
                {'detail': _('Password reset link has been sent to your email address.')}, 
                status=status.HTTP_200_OK
            )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='10/h', method='POST'), name='post')
class PasswordResetConfirmAPIView(APIView):
    """
    Password reset confirm endpoint
    Rate limited: 10 requests per hour per IP
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
                {'detail': _('Invalid reset link')}, 
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
                        {'detail': _('Your password has been successfully changed')}, 
                        status=status.HTTP_200_OK
                    )
                except Exception as e:
                    return Response(
                        {'detail': _('An error occurred while changing password')}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Return validation errors - DRF default format
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Invalid token
            return Response(
                {'detail': _('Reset link is invalid or has expired')}, 
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='user', rate='10/h', method='POST'), name='post')
class PasswordSetAPIView(APIView):
    """
    Password set endpoint for authenticated users without password (social login users)
    Rate limited: 10 requests per hour per user
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Set password for social login users
        """
        # Check if user already has a password
        if request.user.has_usable_password():
            return Response(
                {'detail': _('You already have a password. Use the password-change endpoint to change your password.')},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = PasswordSetSerializer(data=request.data, user=request.user)

        if serializer.is_valid():
            try:
                # Save new password
                serializer.save()

                return Response(
                    {
                        'detail': _('Your password has been successfully created'),
                        'has_password': True
                    },
                    status=status.HTTP_200_OK
                )

            except Exception as e:
                return Response(
                    {'detail': _('An error occurred while creating password')},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='user', rate='10/h', method='POST'), name='post')
class PasswordChangeAPIView(APIView):
    """
    Password change endpoint for authenticated users with existing password
    Rate limited: 10 requests per hour per user
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Change user password
        """
        # Check if user has a password
        if not request.user.has_usable_password():
            return Response(
                {'detail': _('You must create a password first. Use the password-set endpoint.')},
                status=status.HTTP_400_BAD_REQUEST
            )

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


@method_decorator(ratelimit(key='user', rate='3/h', method='POST'), name='post')
class EmailChangeAPIView(APIView):
    """
    Email change request endpoint for authenticated users
    Rate limited: 3 requests per hour per user
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Request email change - sends confirmation to new email
        """
        # Check if user has a password
        if not request.user.has_usable_password():
            return Response(
                {'detail': _('You must create a password first to change your email. Use the password-set endpoint.')},
                status=status.HTTP_400_BAD_REQUEST
            )

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
                    send_template_email(
                        to=new_email,
                        subject='Email Değişikliği Onayı - BP Django App',
                        template_name='accounts/emails/email_change_confirmation',
                        context={
                            'user': request.user,
                            'old_email': request.user.email,
                            'new_email': new_email,
                            'confirmation_link': confirmation_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        sync=True
                    )
                    
                    return Response(
                        {'detail': _('Email change confirmation has been sent to {}. Please check your email.').format(new_email)}, 
                        status=status.HTTP_200_OK
                    )
                    
                except Exception as e:
                    print(f"Email change confirmation email failed: {e}")
                    return Response(
                        {'detail': _('Email sending failed. Please try again.')}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                
            except Exception as e:
                return Response(
                    {'detail': _('An error occurred during email change request')}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeConfirmAPIView(APIView):
    """
    Email change confirmation endpoint
    No rate limiting needed - one-time token use
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
                {'detail': _('Invalid email change link')}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token) and new_email:
            # Check if new email is still available
            if User.objects.filter(email__iexact=new_email).exists():
                return Response(
                    {'detail': _('This email address is now in use. Please try a different email.')}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            old_email = user.email
            
            # Update user email
            user.email = new_email
            user.save()
            
            # Send notification to OLD email address
            try:
                from django.utils import timezone
                send_template_email(
                    to=old_email,
                    subject='Email Adresi Değiştirildi - BP Django App',
                    template_name='accounts/emails/email_change_notification',
                    context={
                        'user': user,
                        'old_email': old_email,
                        'new_email': new_email,
                        'change_date': timezone.now(),
                        'site_url': settings.FRONTEND_URL,
                    },
                    sync=True
                )
            except Exception as e:
                print(f"Email change notification failed: {e}")
            
            return Response({
                'detail': _('Your email address has been successfully changed to {}.').format(new_email),
                'old_email': old_email,
                'new_email': new_email
            }, status=status.HTTP_200_OK)
        else:
            # Invalid token
            return Response(
                {'detail': _('Email change link is invalid or has expired')}, 
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='ip', rate='5/h', method='POST'), name='post')
class EmailVerificationRequestAPIView(APIView):
    """
    Email verification resend endpoint
    Rate limited: 5 requests per hour per IP
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
                        {'detail': _('This email address is already verified')}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Generate verification token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                
                # Create verification link
                verification_link = f"{settings.FRONTEND_URL}/accounts/email-verification-confirm/{uid}/{token}/"
                
                # Send verification email
                try:
                    send_template_email(
                        to=user.email,
                        subject='Email Doğrulama - BP Django App',
                        template_name='accounts/emails/email_verification',
                        context={
                            'user': user,
                            'verification_link': verification_link,
                            'site_url': settings.FRONTEND_URL,
                        },
                        sync=True
                    )
                except Exception as e:
                    print(f"Email verification resend failed: {e}")
                    return Response(
                        {'detail': _('Email sending failed')}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Always return success (security) - DRF default format
            return Response(
                {'detail': _('Email verification link has been sent')}, 
                status=status.HTTP_200_OK
            )
        
        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationConfirmAPIView(APIView):
    """
    Email verification confirm endpoint
    No rate limiting needed - one-time token use
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
                {'detail': _('Invalid verification link')}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token is valid
        if user is not None and default_token_generator.check_token(user, token):
            # Verify user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                
                # Send welcome email after verification (async - non-critical)
                try:
                    send_template_email(
                        to=user.email,
                        subject='Hoş geldiniz! - BP Django App',
                        template_name='accounts/emails/welcome',
                        context={
                            'user': user,
                            'site_url': settings.FRONTEND_URL,
                        },
                        sync=False
                    )
                except Exception as e:
                    print(f"Welcome email failed: {e}")
                
                return Response(
                    {'detail': _('Your email address has been verified! Welcome {}!').format(user.username)}, 
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'detail': _('Your email address is already verified')}, 
                    status=status.HTTP_200_OK
                )
        else:
            # Invalid token
            return Response(
                {'detail': _('Verification link is invalid or has expired')}, 
                status=status.HTTP_400_BAD_REQUEST
            )


@method_decorator(ratelimit(key='ip', rate='15/m', method='POST'), name='post')
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom login view that accepts both username and email
    Rate limited: 15 requests per minute per IP
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def get_serializer_context(self):
        """Add request to serializer context"""
        context = super().get_serializer_context()
        context['request'] = self.request
        return context


class MeAPIView(APIView):
    """
    Current user endpoint - minimal profile data for navbar/UI
    GET: Get current user with minimal profile information
    Requires JWT authentication
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Get current user with minimal profile
        """
        user = request.user

        # Prepare data for serializer
        data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_staff': user.is_staff,
            'is_verified': user.is_verified,
            'has_password': user.has_usable_password(),
            'date_joined': user.date_joined,
            'last_login': user.last_login,
            'profile': user.profile if hasattr(user, 'profile') else None
        }

        # Serialize with request context for full URLs
        serializer = MeSerializer(data, context={'request': request})

        return Response(serializer.data, status=status.HTTP_200_OK)


class ProfileDetailAPIView(APIView):
    """
    Detailed profile endpoint
    GET: Get detailed profile information (bio, birth_date, etc.)
    PATCH: Update profile (first_name, last_name, bio, avatar, birth_date)
    Requires JWT authentication
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Get detailed profile information
        """
        user = request.user

        # Get profile (should exist due to signal)
        if not hasattr(user, 'profile'):
            return Response(
                {'detail': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Serialize with request context for full URLs
        serializer = ProfileDetailSerializer(user.profile, context={'request': request})

        return Response(serializer.data, status=status.HTTP_200_OK)

    @method_decorator(ratelimit(key='user', rate='20/h', method='PATCH'))
    def patch(self, request):
        """
        Update user profile (first_name, last_name, bio, avatar, birth_date)
        Rate limited: 20 requests per hour per user
        """
        serializer = ProfileUpdateSerializer(data=request.data, user=request.user)

        if serializer.is_valid():
            try:
                # Save updated profile
                user = serializer.save()

                # Return detailed profile data
                profile_serializer = ProfileDetailSerializer(user.profile, context={'request': request})

                return Response(profile_serializer.data, status=status.HTTP_200_OK)

            except Exception as e:
                return Response(
                    {'detail': _('An error occurred while updating profile')},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        # Return validation errors - DRF default format
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
