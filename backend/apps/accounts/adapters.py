from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount
from accounts.models import User


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter to handle social login flow
    Mevcut User modelimizle uyumlu hale getiriyor
    """
    
    def pre_social_login(self, request, sociallogin):
        """
        Social login'den önce çalışır
        Mevcut email ile user varsa bağlar
        """
        if sociallogin.user.id:
            return
        
        # Social login'den gelen email
        email = sociallogin.user.email
        if not email:
            return
        
        try:
            # Aynı email ile mevcut user var mı?
            existing_user = User.objects.get(email__iexact=email)
            
            # Social account'u mevcut user'a bağla
            sociallogin.connect(request, existing_user)
            
        except User.DoesNotExist:
            # Yeni user oluşturulacak
            pass
    
    def save_user(self, request, sociallogin, form=None):
        """
        Social login ile user oluşturulurken çalışır
        Bizim User modelimizle uyumlu veriler set eder
        """
        user = sociallogin.user
        
        # Social login'den gelen veriler
        extra_data = sociallogin.account.extra_data
        
        # Email required
        if not user.email:
            user.email = extra_data.get('email', '')
        
        # Username oluştur (email'den)
        if not user.username:
            username_base = user.email.split('@')[0] if user.email else 'user'
            username = username_base
            counter = 1
            
            # Unique username oluştur
            while User.objects.filter(username=username).exists():
                username = f"{username_base}{counter}"
                counter += 1
            
            user.username = username
        
        # Social login ile gelen user'lar verified olsun
        user.is_verified = True

        # User'ı kaydet
        user.save()

        # Profile oluştur veya güncelle
        # Signal otomatik oluşturmuş olmalı, ama yine de get_or_create kullan
        from accounts.models import Profile
        from accounts.social_auth import download_avatar_from_url

        profile, created = Profile.objects.get_or_create(
            user=user,
            defaults={
                'first_name': extra_data.get('given_name', '') or extra_data.get('first_name', ''),
                'last_name': extra_data.get('family_name', '') or extra_data.get('last_name', ''),
                'bio': f"Joined via {sociallogin.account.provider.title()}",
            }
        )

        profile_updated = False

        # Mevcut profile'ı güncelle (boşsa)
        if not profile.first_name:
            profile.first_name = extra_data.get('given_name', '') or extra_data.get('first_name', '')
            profile_updated = True
        if not profile.last_name:
            profile.last_name = extra_data.get('family_name', '') or extra_data.get('last_name', '')
            profile_updated = True

        # Avatar yoksa ve provider'dan geliyorsa download et
        if not profile.avatar:
            avatar_url = self._get_avatar_url(sociallogin.account.provider, extra_data)
            if avatar_url:
                result = download_avatar_from_url(avatar_url, user_id=user.id)
                if result:
                    avatar_file, filename = result
                    profile.avatar.save(filename, avatar_file, save=False)
                    profile_updated = True

        if profile_updated:
            profile.save()
        
        return user
    
    def _get_avatar_url(self, provider, extra_data):
        """
        Provider'a göre avatar URL'ini al

        Args:
            provider (str): Provider name (google, facebook, apple)
            extra_data (dict): Provider'dan gelen extra data

        Returns:
            str: Avatar URL or None
        """
        if provider == 'google':
            # Google: picture field directly contains URL
            return extra_data.get('picture')

        elif provider == 'facebook':
            # Facebook: picture.data.url nested structure
            picture = extra_data.get('picture', {})
            if isinstance(picture, dict):
                picture_data = picture.get('data', {})
                if isinstance(picture_data, dict):
                    return picture_data.get('url')

        elif provider == 'apple':
            # Apple doesn't provide avatar in standard flow
            return None

        return None

    def populate_user(self, request, sociallogin, data):
        """
        User object'ini social login verisiyle doldur

        Note: first_name ve last_name artık Profile modelinde,
        save_user metodunda profile'a kaydedilir.
        """
        user = super().populate_user(request, sociallogin, data)
        return user
