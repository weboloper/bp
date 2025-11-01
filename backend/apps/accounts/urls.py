from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),

    # password urls
    path('password-reset-request/', views.password_reset_request_view, name='password_reset_request'),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),

    # email verification urls
    path('email-verification-request/', views.email_verification_request_view, name='email_verification_request'),
    path('email-verification-confirm/<uidb64>/<token>/', views.email_verification_confirm_view, name='email_verification_confirm'),
    
    # password set & change urls
    path('password-set/', views.password_set_view, name='password_set'),
    path('password-change/', views.password_change_view, name='password_change'),
    
    # email change urls
    path('email-change/', views.email_change_view, name='email_change'),
    path('email-change-confirm/<uidb64>/<token>/<new_email_b64>/', views.email_change_confirm_view, name='email_change_confirm'),
    
    # profile update urls
    path('profile-update/', views.profile_update_view, name='profile_update'),
    path('username-change/', views.username_change_view, name='username_change'),
    
    # Google OAuth urls
    path('google-login/', views.google_login_view, name='google_login'),
    path('google-callback/', views.google_callback_view, name='google_callback'),
    
    # Apple OAuth urls
    path('apple-login/', views.apple_login_view, name='apple_login'),
    path('apple-callback/', views.apple_callback_view, name='apple_callback'),
    
    # Facebook OAuth urls
    path('facebook-login/', views.facebook_login_view, name='facebook_login'),
    path('facebook-callback/', views.facebook_callback_view, name='facebook_callback'),
]
