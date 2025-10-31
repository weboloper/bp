from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from .views import (
    CustomTokenObtainPairView,
    MeAPIView,
    RegisterAPIView,
    PasswordResetAPIView,
    PasswordResetConfirmAPIView,
    EmailVerificationResendAPIView,
    EmailVerificationConfirmAPIView,
    PasswordSetAPIView,
    PasswordChangeAPIView,
    EmailChangeAPIView,
    EmailChangeConfirmAPIView,
    UsernameChangeAPIView,
    GoogleSocialLoginAPIView,
    FacebookSocialLoginAPIView,  # ✅ Eklendi
    AppleSocialLoginAPIView
)
# Cookie-based views (Farklı host için devre dışı)
# from .auth_views import (
#     login_cookie,
#     logout_cookie,
#     token_verify_cookie,
#     token_refresh_cookie
# )

app_name = 'accounts_api'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', RegisterAPIView.as_view(), name='register'),
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Password reset endpoints
    path('auth/password-reset/', PasswordResetAPIView.as_view(), name='password_reset'),
    path('auth/password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),
    
    # Email verification endpoints
    path('auth/email-verify-resend/', EmailVerificationResendAPIView.as_view(), name='email_verification_resend'),
    path('auth/email-verify/<uidb64>/<token>/', EmailVerificationConfirmAPIView.as_view(), name='email_verification_confirm'),

    # Password set & change endpoints (authenticated)
    path('auth/password-set/', PasswordSetAPIView.as_view(), name='password_set'),
    path('auth/password-change/', PasswordChangeAPIView.as_view(), name='password_change'),
    
    # Email change endpoints (authenticated)
    path('auth/email-change/', EmailChangeAPIView.as_view(), name='email_change'),
    path('auth/email-change-confirm/<uidb64>/<token>/<new_email_b64>/', EmailChangeConfirmAPIView.as_view(), name='email_change_confirm'),
    
    # Username change endpoint (authenticated)
    path('auth/username-change/', UsernameChangeAPIView.as_view(), name='username_change'),
    
    # Social login endpoints
    path('auth/social/google/', GoogleSocialLoginAPIView.as_view(), name='google_social_login'),
    path('auth/social/facebook/', FacebookSocialLoginAPIView.as_view(), name='facebook_social_login'),  # ✅ Eklendi
    path('auth/social/apple/', AppleSocialLoginAPIView.as_view(), name='apple_social_login'),
    
    # User profile endpoints - RESTful design
    path('me/', MeAPIView.as_view(), name='current_user'),  # GET: profile, PATCH: update
    
    # Cookie-based endpoints (Farklı host'ta çalışmaz - devre dışı)
    # path('auth/login-cookie/', login_cookie, name='login_cookie'),
    # path('auth/logout-cookie/', logout_cookie, name='logout_cookie'),
    # path('auth/token/verify-cookie/', token_verify_cookie, name='token_verify_cookie'),
    # path('auth/token/refresh-cookie/', token_refresh_cookie, name='token_refresh_cookie'),
]
