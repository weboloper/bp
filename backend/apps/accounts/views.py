from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.conf import settings
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from accounts.models import User, Profile
from accounts.utils import validate_alphanumeric_username
from accounts.forms import UserRegistrationForm, PasswordResetForm, PasswordResetConfirmForm, EmailVerificationResendForm, PasswordSetForm, PasswordChangeForm, EmailChangeForm, ProfileUpdateForm, ProfileDetailsForm, UsernameChangeForm
from core.email_service import EmailService
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import requests
import secrets
import urllib.parse
from accounts.social_auth import GoogleAuth

def register_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        
        if form.is_valid():
            try:
                user = form.save()
                
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
                    
                    messages.success(request, 'Kayıt başarılı! Email adresinize doğrulama linki gönderildi.')
                except Exception as e:
                    print(f"Email verification email failed: {e}")
                    messages.warning(request, 'Kayıt başarılı ama email gönderiminde sorun oluştu. Giriş yapmayı deneyin.')
                
                return render(request, 'accounts/public/register.html')
                    
            except Exception as e:
                messages.error(request, 'Kayıt sırasında bir hata oluştu')
        
        # Return errors
        return render(request, 'accounts/public/register.html', {
            'errors': form.errors,
            'username': request.POST.get('username', ''),
            'email': request.POST.get('email', '')
        })
    
    # GET request
    return render(request, 'accounts/public/register.html')

def login_view(request):
    if request.method == 'POST':
        errors = {}
        
        # Form data
        username = request.POST.get('username', '').strip()  # Updated field name
        password = request.POST.get('password', '')
        
        # Basic validation
        if not username:
            errors['username'] = 'Email veya kullanıcı adı gerekli'
        
        if not password:
            errors['password'] = 'Şifre gerekli'
        
        # If basic validation passes, try authentication
        if not errors:
            user = None
            
            # Check if username is email or username
            if '@' in username:
                # It's an email
                try:
                    validate_email(username)
                    # Find user by email
                    try:
                        user_obj = User.objects.get(email=username)
                        user = authenticate(request, username=user_obj.username, password=password)
                    except User.DoesNotExist:
                        errors['username'] = 'Bu email adresi ile kayıtlı kullanıcı bulunamadı'
                except ValidationError:
                    errors['username'] = 'Geçerli bir email adresi giriniz'
            else:
                # It's a username
                user = authenticate(request, username=username, password=password)
            
            # Check authentication result
            if user is not None:
                if user.is_active:
                    if not user.is_verified:
                        messages.warning(request, 'Hesabınız henüz doğrulanmamış. Email adresinizi kontrol edin.')
                        return render(request, 'accounts/public/login.html', {
                            'errors': {},
                            'username': username,
                            'show_verification_link': True
                        })
                    
                    login(request, user)
                    messages.success(request, f'Hoş geldin {user.username}!')
                    
                    # Redirect to next page or profile
                    next_url = request.GET.get('next', 'accounts:profile')
                    return redirect(next_url)
                else:
                    errors['username'] = 'Hesabınız devre dışı bırakılmış'
            else:
                if '@' in username:
                    errors['password'] = 'Email veya şifre hatalı'
                else:
                    errors['password'] = 'Kullanıcı adı veya şifre hatalı'
        
        # Return errors
        return render(request, 'accounts/public/login.html', {
            'errors': errors,
            'username': username
        })
    
    # GET request
    return render(request, 'accounts/public/login.html')

def profile_view(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    return render(request, 'accounts/private/profile.html', {
        'user': request.user,
        'profile': request.user.profile
    })

def logout_view(request):
    if request.user.is_authenticated:
        username = request.user.username
        logout(request)
        messages.success(request, f'Hoşçakal {username}! Başarıyla çıkış yaptınız.')
    
    return redirect('home')

def password_reset_view(request):
    """Şifremi unuttum formu"""
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        
        if form.is_valid():
            user = form.get_user()
            
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
                    
                    messages.success(request, 'Şifre sıfırlama linki email adresinize gönderildi.')
                    return redirect('home')
                    
                except Exception as e:
                    print(f"Password reset email failed: {e}")
                    form.add_error('email', 'Email gönderimi başarısız. Lütfen tekrar deneyin.')
            else:
                # Security: Don't reveal if email exists
                messages.success(request, 'Şifre sıfırlama linki email adresinize gönderildi.')
                return redirect('home')
        
        return render(request, 'accounts/public/password_reset.html', {
            'errors': form.errors,
            'email': request.POST.get('email', '')
        })
    
    return render(request, 'accounts/public/password_reset.html')

def password_reset_confirm_view(request, uidb64, token):
    """Email'den gelen link ile şifre sıfırlama"""
    try:
        # Decode user ID
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    # Check if token is valid
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = PasswordResetConfirmForm(user, request.POST)
            
            if form.is_valid():
                form.save()
                messages.success(request, 'Şifreniz başarıyla değiştirildi. Yeni şifrenizle giriş yapabilirsiniz.')
                return redirect('accounts:login')
            
            return render(request, 'accounts/public/password_reset_confirm.html', {
                'errors': form.errors,
                'validlink': True,
                'uidb64': uidb64,
                'token': token
            })
        
        # GET request with valid token
        return render(request, 'accounts/public/password_reset_confirm.html', {
            'validlink': True,
            'uidb64': uidb64,
            'token': token
        })
    else:
        # Invalid token
        return render(request, 'accounts/public/password_reset_confirm.html', {
            'validlink': False
        })

def email_verification_confirm_view(request, uidb64, token):
    """Email doğrulama linki ile hesap doğrulama"""
    try:
        # Decode user ID
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
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
            
            messages.success(request, f'Email adresiniz doğrulandı! Hoş geldin {user.username}!')
        else:
            messages.info(request, 'Email adresiniz zaten doğrulanmış.')
        
        return render(request, 'accounts/public/email_verification_confirm.html', {
            'validlink': True
        })
    else:
        # Invalid token
        return render(request, 'accounts/public/email_verification_confirm.html', {
            'validlink': False
        })

def email_verification_resend_view(request):
    """Email doğrulama yeniden gönderme formu"""
    if request.method == 'POST':
        form = EmailVerificationResendForm(request.POST)
        
        if form.is_valid():
            user = form.get_user()
            
            if user:
                if user.is_verified:
                    messages.info(request, 'Bu email adresi zaten doğrulanmış.')
                    return redirect('accounts:login')
                
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
                    
                    messages.success(request, 'Email doğrulama linki gönderildi.')
                    return redirect('accounts:login')
                    
                except Exception as e:
                    print(f"Email verification resend failed: {e}")
                    form.add_error('email', 'Email gönderimi başarısız. Lütfen tekrar deneyin.')
            else:
                # Security: Don't reveal if email exists
                messages.success(request, 'Eğer bu email adresi kayıtlıysa, doğrulama linki gönderildi.')
                return redirect('accounts:login')
        
        return render(request, 'accounts/public/email_verification_resend.html', {
            'errors': form.errors,
            'email': request.POST.get('email', '')
        })
    
    return render(request, 'accounts/public/email_verification_resend.html')

def password_change_view(request):
    """
    Login olan kullanıcının şifre değiştirme/oluşturma formu

    - Sosyal medya ile giriş yapanlar: PasswordSetForm (current password gerektirmez)
    - Normal kullanıcılar: PasswordChangeForm (current password gerektirir)
    """
    if not request.user.is_authenticated:
        return redirect('accounts:login')

    # Kullanıcının password'ü var mı kontrol et
    has_password = request.user.has_usable_password()

    # Sosyal medya kullanıcısı için farklı form
    FormClass = PasswordChangeForm if has_password else PasswordSetForm

    if request.method == 'POST':
        form = FormClass(request.user, request.POST)

        if form.is_valid():
            form.save()

            # Update session to keep user logged in after password change
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, request.user)

            # Sosyal medya kullanıcısı ilk defa password oluşturduysa
            success_message = 'Şifreniz başarıyla oluşturuldu.' if not has_password else 'Şifreniz başarıyla değiştirildi.'
            messages.success(request, success_message)
            return redirect('accounts:profile')

        return render(request, 'accounts/private/password_change.html', {
            'form': form,
            'errors': form.errors,
            'has_password': has_password
        })

    form = FormClass(request.user)
    return render(request, 'accounts/private/password_change.html', {
        'form': form,
        'has_password': has_password
    })

def email_change_view(request):
    """Login olan kullanıcının email değiştirme formu"""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    if request.method == 'POST':
        form = EmailChangeForm(request.user, request.POST)
        
        if form.is_valid():
            new_email = form.cleaned_data['new_email']
            
            # Generate email change token
            token = default_token_generator.make_token(request.user)
            uid = urlsafe_base64_encode(force_bytes(request.user.pk))
            
            # Create confirmation link
            confirmation_link = f"{settings.FRONTEND_URL}/accounts/email-change-confirm/{uid}/{token}/{urlsafe_base64_encode(force_bytes(new_email))}/"
            
            try:
                # Send confirmation email to NEW email address
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
                
                messages.success(request, f'Email değişiklik onayı {new_email} adresine gönderildi. Lütfen emailinizi kontrol edin.')
                return redirect('accounts:profile')
                
            except Exception as e:
                print(f"Email change confirmation email failed: {e}")
                form.add_error('new_email', 'Email gönderimi başarısız. Lütfen tekrar deneyin.')
        
        return render(request, 'accounts/private/email_change.html', {
            'errors': form.errors,
            'new_email': request.POST.get('new_email', '')
        })
    
    return render(request, 'accounts/private/email_change.html')

def email_change_confirm_view(request, uidb64, token, new_email_b64):
    """Email değişiklik onay linki"""
    try:
        # Decode user ID and new email
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        new_email = force_str(urlsafe_base64_decode(new_email_b64))
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        new_email = None
    
    # Check if token is valid
    if user is not None and default_token_generator.check_token(user, token) and new_email:
        # Check if new email is still available
        if User.objects.filter(email__iexact=new_email).exists():
            messages.error(request, 'Bu email adresi artık kullanılıyor. Lütfen farklı bir email deneyin.')
            return render(request, 'accounts/public/email_change_confirm.html', {'validlink': False})
        
        old_email = user.email
        
        # Update user email
        user.email = new_email
        user.save()
        
        # Send notification to OLD email address
        try:
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
        
        messages.success(request, f'Email adresiniz başarıyla {new_email} olarak değiştirildi.')
        
        return render(request, 'accounts/public/email_change_confirm.html', {
            'validlink': True,
            'old_email': old_email,
            'new_email': new_email
        })
    else:
        # Invalid token
        return render(request, 'accounts/public/email_change_confirm.html', {
            'validlink': False
        })

def profile_update_view(request):
    """Profil bilgilerini güncelleme"""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    # Get or create profile (signal should have created it, but use get_or_create to be safe)
    profile, created = Profile.objects.get_or_create(
        user=request.user,
        defaults={
            'birth_date': None,
            'bio': '',
            'avatar': None
        }
    )
    
    if request.method == 'POST':
        user_form = ProfileUpdateForm(request.user, request.POST)
        profile_form = ProfileDetailsForm(request.POST, request.FILES, instance=profile)
        
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            
            messages.success(request, 'Profiliniz başarıyla güncellendi.')
            return redirect('accounts:profile')
    else:
        user_form = ProfileUpdateForm(request.user)
        profile_form = ProfileDetailsForm(instance=profile)
    
    return render(request, 'accounts/private/profile_update.html', {
        'user_form': user_form,
        'profile_form': profile_form
    })

def username_change_view(request):
    """Kullanıcı adı değiştirme formu"""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    if request.method == 'POST':
        form = UsernameChangeForm(request.user, request.POST)
        
        if form.is_valid():
            old_username = request.user.username
            form.save()
            
            # Update session to keep user logged in after username change
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, request.user)
            
            messages.success(request, f'Kullanıcı adınız başarıyla "{old_username}" adresinden "{request.user.username}" olarak değiştirildi.')
            return redirect('accounts:profile')
        
        return render(request, 'accounts/private/username_change.html', {
            'errors': form.errors,
            'new_username': request.POST.get('new_username', '')
        })
    
    return render(request, 'accounts/private/username_change.html')

def apple_login_view(request):
    """Apple Sign In başlatma"""
    # Apple OAuth URL'i oluştur
    apple_auth_url = 'https://appleid.apple.com/auth/authorize'
    
    # Redirect URI - callback URL
    redirect_uri = request.build_absolute_uri('/accounts/apple-callback/')
    
    # State parametresi - CSRF koruması için
    state = secrets.token_urlsafe(32)
    request.session['apple_oauth_state'] = state
    
    # OAuth parametreleri
    params = {
        'client_id': settings.APPLE_CLIENT_ID,  # ✔️ Güncellendi
        'redirect_uri': redirect_uri,
        'response_type': 'code id_token',
        'response_mode': 'form_post',
        'scope': 'name email',
        'state': state,
    }
    
    # Apple OAuth URL'ine yönlendir
    auth_url = f"{apple_auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

def apple_callback_view(request):
    """Apple Sign In callback - Full BaseSocialAuth Pattern"""
    # Apple, form_post mode kullanır, POST request gelir
    if request.method != 'POST':
        messages.error(request, 'Apple login başarısız: Geçersiz request')
        return redirect('accounts:login')
    
    # Hata kontrolü
    error = request.POST.get('error')
    if error:
        messages.error(request, f'Apple login iptal edildi: {error}')
        return redirect('accounts:login')
    
    # Authorization code ve user data al
    code = request.POST.get('code')
    id_token = request.POST.get('id_token')
    user_json = request.POST.get('user')  # İlk login'de gelir
    state = request.POST.get('state')
    
    if not id_token or not state:
        messages.error(request, 'Apple login başarısız: Eksik parametreler')
        return redirect('accounts:login')
    
    # State doğrulama (CSRF koruması)
    stored_state = request.session.get('apple_oauth_state')
    if not stored_state or state != stored_state:
        messages.error(request, 'Apple login başarısız: Güvenlik doğrulaması başarısız')
        return redirect('accounts:login')
    
    # State'i temizle
    del request.session['apple_oauth_state']
    
    try:
        # BaseSocialAuth FULL FLOW - Google ile aynı pattern!
        from accounts.social_auth import AppleAuth
        
        apple_auth = AppleAuth()
        user = apple_auth.authenticate(id_token)
        
        # Apple'a özel: İlk login'de isim bilgisi ayrı JSON'da gelir
        # Bu bilgiyi yakalayarak profile'ı güncelle
        if user_json:
            try:
                import json
                user_info = json.loads(user_json)
                name = user_info.get('name', {})
                first_name = name.get('firstName', '')
                last_name = name.get('lastName', '')

                # Profile'ı güncelle (sadece isim boşsa)
                try:
                    profile = user.profile
                    profile_updated = False

                    if first_name and not profile.first_name:
                        profile.first_name = first_name
                        profile_updated = True
                    if last_name and not profile.last_name:
                        profile.last_name = last_name
                        profile_updated = True

                    if profile_updated:
                        profile.save()

                except Exception as profile_error:
                    print(f"Apple login - Profile güncelleme hatası: {profile_error}")

            except Exception as e:
                # İsim bilgisi alınamazsa devam et
                print(f"Apple login - İsim bilgisi alınamadı: {e}")
        
        # Kullanıcıyı login et
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        messages.success(request, f'Apple ile giriş başarılı! Hoş geldin {user.username}!')
        
        return redirect('accounts:profile')
        
    except ValidationError as e:
        messages.error(request, f'Apple login başarısız: {str(e)}')
        return redirect('accounts:login')
    except Exception as e:
        messages.error(request, f'Apple login başarısız: {str(e)}')
        return redirect('accounts:login')

def google_login_view(request):
    """Google OAuth login başlatma"""
    # Google OAuth URL'i oluştur
    google_auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    
    # Redirect URI - callback URL
    redirect_uri = request.build_absolute_uri('/accounts/google-callback/')
    
    # State parametresi - CSRF koruması için
    state = secrets.token_urlsafe(32)
    request.session['google_oauth_state'] = state
    
    # OAuth parametreleri
    params = {
        'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'online',
        'prompt': 'select_account'
    }
    
    # Google OAuth URL'ine yönlendir
    auth_url = f"{google_auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

def google_callback_view(request):
    """Google OAuth callback - Refactored with BaseSocialAuth"""
    # Hata kontrolü
    error = request.GET.get('error')
    if error:
        messages.error(request, f'Google login iptal edildi: {error}')
        return redirect('accounts:login')
    
    # Authorization code al
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    if not code or not state:
        messages.error(request, 'Google login başarısız: Eksik parametreler')
        return redirect('accounts:login')
    
    # State doğrulama (CSRF koruması)
    stored_state = request.session.get('google_oauth_state')
    if not stored_state or state != stored_state:
        messages.error(request, 'Google login başarısız: Güvenlik doğrulaması başarısız')
        return redirect('accounts:login')
    
    # State'i temizle
    del request.session['google_oauth_state']
    
    try:
        # Authorization code ile access token al
        token_url = 'https://oauth2.googleapis.com/token'
        redirect_uri = request.build_absolute_uri('/accounts/google-callback/')
        
        token_data = {
            'code': code,
            'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
            'client_secret': settings.GOOGLE_OAUTH2_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        token_response = requests.post(token_url, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            messages.error(request, 'Google login başarısız: Token alınamadı')
            return redirect('accounts:login')
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        if not access_token:
            messages.error(request, 'Google login başarısız: Access token bulunamadı')
            return redirect('accounts:login')
        
        # BaseSocialAuth kullanarak authenticate et
        google_auth = GoogleAuth()
        user = google_auth.authenticate(access_token)
        
        # Kullanıcıyı login et
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        messages.success(request, f'Google ile giriş başarılı! Hoş geldin {user.username}!')
        
        return redirect('accounts:profile')
        
    except ValidationError as e:
        messages.error(request, f'Google login başarısız: {str(e)}')
        return redirect('accounts:login')
    except requests.RequestException as e:
        messages.error(request, f'Google login başarısız: Network hatası - {str(e)}')
        return redirect('accounts:login')
    except Exception as e:
        messages.error(request, f'Google login başarısız: {str(e)}')
        return redirect('accounts:login')

def facebook_login_view(request):
    """Facebook OAuth login başlatma"""
    # Facebook OAuth URL'i oluştur
    facebook_auth_url = 'https://www.facebook.com/v18.0/dialog/oauth'
    
    # Redirect URI - callback URL
    redirect_uri = request.build_absolute_uri('/accounts/facebook-callback/')
    
    # State parametresi - CSRF koruması için
    state = secrets.token_urlsafe(32)
    request.session['facebook_oauth_state'] = state
    
    # OAuth parametreleri
    params = {
        'client_id': settings.FACEBOOK_APP_ID,
        'redirect_uri': redirect_uri,
        'state': state,
        'scope': 'email,public_profile',
        'response_type': 'code',
    }
    
    # Facebook OAuth URL'ine yönlendir
    auth_url = f"{facebook_auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

def facebook_callback_view(request):
    """Facebook OAuth callback - Full BaseSocialAuth Pattern"""
    # Hata kontrolü
    error = request.GET.get('error')
    if error:
        error_description = request.GET.get('error_description', 'Bilinmeyen hata')
        messages.error(request, f'Facebook login iptal edildi: {error_description}')
        return redirect('accounts:login')
    
    # Authorization code al
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    if not code or not state:
        messages.error(request, 'Facebook login başarısız: Eksik parametreler')
        return redirect('accounts:login')
    
    # State doğrulama (CSRF koruması)
    stored_state = request.session.get('facebook_oauth_state')
    if not stored_state or state != stored_state:
        messages.error(request, 'Facebook login başarısız: Güvenlik doğrulaması başarısız')
        return redirect('accounts:login')
    
    # State'i temizle
    del request.session['facebook_oauth_state']
    
    try:
        # Authorization code ile access token al
        token_url = 'https://graph.facebook.com/v18.0/oauth/access_token'
        redirect_uri = request.build_absolute_uri('/accounts/facebook-callback/')
        
        token_params = {
            'client_id': settings.FACEBOOK_APP_ID,
            'client_secret': settings.FACEBOOK_APP_SECRET,
            'code': code,
            'redirect_uri': redirect_uri,
        }
        
        token_response = requests.get(token_url, params=token_params, timeout=10)
        
        if token_response.status_code != 200:
            messages.error(request, 'Facebook login başarısız: Token alınamadı')
            return redirect('accounts:login')
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        if not access_token:
            messages.error(request, 'Facebook login başarısız: Access token bulunamadı')
            return redirect('accounts:login')
        
        # BaseSocialAuth FULL FLOW - Google ve Apple ile aynı pattern!
        from accounts.social_auth import FacebookAuth
        
        facebook_auth = FacebookAuth()
        user = facebook_auth.authenticate(access_token)
        
        # Kullanıcıyı login et
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        messages.success(request, f'Facebook ile giriş başarılı! Hoş geldin {user.username}!')
        
        return redirect('accounts:profile')
        
    except ValidationError as e:
        messages.error(request, f'Facebook login başarısız: {str(e)}')
        return redirect('accounts:login')
    except requests.RequestException as e:
        messages.error(request, f'Facebook login başarısız: Network hatası - {str(e)}')
        return redirect('accounts:login')
    except Exception as e:
        messages.error(request, f'Facebook login başarısız: {str(e)}')
        return redirect('accounts:login')