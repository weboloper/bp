from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth import authenticate, get_user_model
from .utils import get_token_from_cookie, set_jwt_cookies, clear_jwt_cookies

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def login_cookie(request):
    """
    Cookie-based login endpoint'i
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {'error': 'Kullanıcı adı ve şifre gerekli'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Kullanıcıyı doğrula
    user = authenticate(username=username, password=password)
    
    if user is None:
        return Response(
            {'error': 'Geçersiz kullanıcı adı veya şifre'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    if not user.is_active:
        return Response(
            {'error': 'Kullanıcı hesabı devre dışı'}, 
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Başarılı login response'u oluştur
    response = Response(
        {
            'message': 'Başarıyla giriş yapıldı',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_verified': user.is_verified
            }
        }, 
        status=status.HTTP_200_OK
    )
    
    # Token'ları cookie'ye set et
    response = set_jwt_cookies(response, user)
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def logout_cookie(request):
    """
    Cookie-based logout endpoint'i
    """
    response = Response(
        {'message': 'Başarıyla çıkış yapıldı'}, 
        status=status.HTTP_200_OK
    )
    
    # Cookie'leri temizle
    response = clear_jwt_cookies(response)
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def token_verify_cookie(request):
    """
    Cookie'den token doğrulama endpoint'i
    """
    token = get_token_from_cookie(request, 'access_token')
    
    if not token:
        return Response(
            {'error': 'Access token cookie bulunamadı'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Token'ı doğrula
        UntypedToken(token)
        return Response(
            {'valid': True, 'message': 'Token geçerli'}, 
            status=status.HTTP_200_OK
        )
    except (InvalidToken, TokenError) as e:
        return Response(
            {
                'valid': False, 
                'error': 'Token geçersiz veya süresi dolmuş',
                'detail': str(e)
            }, 
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def token_refresh_cookie(request):
    """
    Cookie'den token yenileme endpoint'i
    """
    refresh_token = get_token_from_cookie(request, 'refresh_token')
    
    if not refresh_token:
        return Response(
            {'error': 'Refresh token cookie bulunamadı'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Refresh token'ı doğrula ve yeni access token oluştur
        refresh = RefreshToken(refresh_token)
        new_access_token = str(refresh.access_token)
        
        # Response oluştur ve yeni access token'ı cookie'ye set et
        response = Response(
            {
                'message': 'Token başarıyla yenilendi'
            }, 
            status=status.HTTP_200_OK
        )
        
        # Yeni access token'ı cookie'ye set et
        response.set_cookie(
            'access_token',
            new_access_token,
            max_age=900,  # 15 dakika
            httponly=True,
            samesite='Lax',
            secure=False  # Development için False, production'da True
        )
        
        return response
        
    except (InvalidToken, TokenError) as e:
        return Response(
            {
                'error': 'Refresh token geçersiz veya süresi dolmuş',
                'detail': str(e)
            }, 
            status=status.HTTP_401_UNAUTHORIZED
        )
