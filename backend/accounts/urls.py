from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),

    # password urls
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    
    # email verification urls
    path('email-verify/<uidb64>/<token>/', views.email_verification_confirm_view, name='email_verification_confirm'),
    path('email-verify-resend/', views.email_verification_resend_view, name='email_verification_resend'),
    
    # password change url
    path('password-change/', views.password_change_view, name='password_change'),
    
    # email change urls
    path('email-change/', views.email_change_view, name='email_change'),
    path('email-change-confirm/<uidb64>/<token>/<new_email_b64>/', views.email_change_confirm_view, name='email_change_confirm'),
    
    # profile update urls
    path('profile-update/', views.profile_update_view, name='profile_update'),
    path('username-change/', views.username_change_view, name='username_change'),
]
