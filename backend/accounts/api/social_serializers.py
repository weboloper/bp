"""
Social Login Serializers - Refactored with BaseSocialAuth

Bu modül API için social login serializer'larını içerir.
BaseSocialAuth pattern kullanılarak refactor edilmiştir.
"""

from rest_framework import serializers
from django.core.exceptions import ValidationError
from accounts.social_auth import GoogleAuth, FacebookAuth, AppleAuth


class GoogleSocialLoginSerializer(serializers.Serializer):
    """
    Google Social Login Serializer - Refactored with BaseSocialAuth
    Frontend'den gelen Google access token'i verify eder ve user döner
    
    Usage:
        serializer = GoogleSocialLoginSerializer(data={'access_token': token})
        if serializer.is_valid():
            user = serializer.save()
    """
    access_token = serializers.CharField(required=True)
    
    def validate_access_token(self, value):
        """Google access token'i doğrula"""
        access_token = value.strip()
        
        if not access_token:
            raise serializers.ValidationError('Google access token gerekli')
        
        return access_token
    
    def save(self):
        """
        Google access token'i verify et ve user döndür
        
        BaseSocialAuth kullanarak tüm iş mantığını delegate eder.
        """
        access_token = self.validated_data['access_token']
        
        try:
            # BaseSocialAuth pattern kullan
            google_auth = GoogleAuth()
            user = google_auth.authenticate(access_token)
            return user
        except ValidationError as e:
            raise serializers.ValidationError(str(e))


class FacebookSocialLoginSerializer(serializers.Serializer):
    """
    Facebook Social Login Serializer - Refactored with BaseSocialAuth
    Frontend'den gelen Facebook access token'i verify eder ve user döner
    
    Usage:
        serializer = FacebookSocialLoginSerializer(data={'access_token': token})
        if serializer.is_valid():
            user = serializer.save()
    """
    access_token = serializers.CharField(required=True)
    
    def validate_access_token(self, value):
        """Facebook access token'i doğrula"""
        access_token = value.strip()
        
        if not access_token:
            raise serializers.ValidationError('Facebook access token gerekli')
        
        return access_token
    
    def save(self):
        """
        Facebook access token'i verify et ve user döndür
        
        BaseSocialAuth kullanarak tüm iş mantığını delegate eder.
        """
        access_token = self.validated_data['access_token']
        
        try:
            # BaseSocialAuth pattern kullan
            facebook_auth = FacebookAuth()
            user = facebook_auth.authenticate(access_token)
            return user
        except ValidationError as e:
            raise serializers.ValidationError(str(e))


class AppleSocialLoginSerializer(serializers.Serializer):
    """
    Apple Social Login Serializer - Refactored with BaseSocialAuth
    Frontend'den gelen Apple identity token'i verify eder ve user döner
    
    NOT: Apple Sign In henüz fully implement edilmemiştir.
    JWT token verification ve Apple public key validation gerekiyor.
    
    Usage:
        serializer = AppleSocialLoginSerializer(data={'identity_token': token})
        if serializer.is_valid():
            user = serializer.save()
    """
    identity_token = serializers.CharField(required=True)
    
    def validate_identity_token(self, value):
        """Apple identity token'i doğrula"""
        identity_token = value.strip()
        
        if not identity_token:
            raise serializers.ValidationError('Apple identity token gerekli')
        
        return identity_token
    
    def save(self):
        """
        Apple identity token'i verify et ve user döndür
        
        BaseSocialAuth kullanarak tüm iş mantığını delegate eder.
        """
        identity_token = self.validated_data['identity_token']
        
        try:
            # BaseSocialAuth pattern kullan
            apple_auth = AppleAuth()
            user = apple_auth.authenticate(identity_token)
            return user
        except NotImplementedError:
            raise serializers.ValidationError(
                'Apple Sign In henüz implement edilmedi. '
                'JWT token verification ve Apple public key validation gerekiyor.'
            )
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
