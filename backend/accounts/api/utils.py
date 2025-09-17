from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken


def set_jwt_cookies(response, user):
    """
    Access ve refresh token'ları httpOnly cookie olarak set eder
    """
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    
    # Access token cookie
    response.set_cookie(
        'access_token',
        access_token,
        max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
        httponly=True,
        samesite='Lax',
        secure=not settings.DEBUG  # HTTPS'de secure=True
    )
    
    # Refresh token cookie  
    response.set_cookie(
        'refresh_token',
        refresh_token,
        max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
        httponly=True,
        samesite='Lax',
        secure=not settings.DEBUG  # HTTPS'de secure=True
    )
    
    return response


def get_token_from_cookie(request, token_type='access_token'):
    """
    Cookie'den token'ı alır
    """
    return request.COOKIES.get(token_type)


def clear_jwt_cookies(response):
    """
    JWT cookie'lerini temizler
    """
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response
