from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.conf import settings
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from accounts.models import User
from accounts.utils import validate_alphanumeric_username
from accounts.forms import UserRegistrationForm, PasswordResetForm, PasswordResetConfirmForm, EmailVerificationResendForm, PasswordChangeForm
from core.email_service import EmailService
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

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
                
                return render(request, 'accounts/register.html')
                    
            except Exception as e:
                messages.error(request, 'Kayıt sırasında bir hata oluştu')
        
        # Return errors
        return render(request, 'accounts/register.html', {
            'errors': form.errors,
            'username': request.POST.get('username', ''),
            'email': request.POST.get('email', '')
        })
    
    # GET request
    return render(request, 'accounts/register.html')

def login_view(request):
    if request.method == 'POST':
        errors = {}
        
        # Form data
        login_field = request.POST.get('login_field', '').strip()  # Email veya username
        password = request.POST.get('password', '')
        
        # Basic validation
        if not login_field:
            errors['login_field'] = 'Email veya kullanıcı adı gerekli'
        
        if not password:
            errors['password'] = 'Şifre gerekli'
        
        # If basic validation passes, try authentication
        if not errors:
            user = None
            
            # Check if login_field is email or username
            if '@' in login_field:
                # It's an email
                try:
                    validate_email(login_field)
                    # Find user by email
                    try:
                        user_obj = User.objects.get(email=login_field)
                        user = authenticate(request, username=user_obj.username, password=password)
                    except User.DoesNotExist:
                        errors['login_field'] = 'Bu email adresi ile kayıtlı kullanıcı bulunamadı'
                except ValidationError:
                    errors['login_field'] = 'Geçerli bir email adresi giriniz'
            else:
                # It's a username
                user = authenticate(request, username=login_field, password=password)
            
            # Check authentication result
            if user is not None:
                if user.is_active:
                    if not user.is_verified:
                        messages.warning(request, 'Hesabınız henüz doğrulanmamış. Email adresinizi kontrol edin.')
                        return render(request, 'accounts/login.html', {
                            'errors': {},
                            'login_field': login_field,
                            'show_verification_link': True
                        })
                    
                    login(request, user)
                    messages.success(request, f'Hoş geldin {user.username}!')
                    
                    # Redirect to next page or profile
                    next_url = request.GET.get('next', 'accounts:profile')
                    return redirect(next_url)
                else:
                    errors['login_field'] = 'Hesabınız devre dışı bırakılmış'
            else:
                if '@' in login_field:
                    errors['password'] = 'Email veya şifre hatalı'
                else:
                    errors['password'] = 'Kullanıcı adı veya şifre hatalı'
        
        # Return errors
        return render(request, 'accounts/login.html', {
            'errors': errors,
            'login_field': login_field
        })
    
    # GET request
    return render(request, 'accounts/login.html')

def profile_view(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    return render(request, 'accounts/profile.html', {
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
        
        return render(request, 'accounts/password_reset.html', {
            'errors': form.errors,
            'email': request.POST.get('email', '')
        })
    
    return render(request, 'accounts/password_reset.html')

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
            
            return render(request, 'accounts/password_reset_confirm.html', {
                'errors': form.errors,
                'validlink': True,
                'uidb64': uidb64,
                'token': token
            })
        
        # GET request with valid token
        return render(request, 'accounts/password_reset_confirm.html', {
            'validlink': True,
            'uidb64': uidb64,
            'token': token
        })
    else:
        # Invalid token
        return render(request, 'accounts/password_reset_confirm.html', {
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
        
        return render(request, 'accounts/email_verification_confirm.html', {
            'validlink': True
        })
    else:
        # Invalid token
        return render(request, 'accounts/email_verification_confirm.html', {
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
        
        return render(request, 'accounts/email_verification_resend.html', {
            'errors': form.errors,
            'email': request.POST.get('email', '')
        })
    
    return render(request, 'accounts/email_verification_resend.html')

def password_change_view(request):
    """Login olan kullanıcının şifre değiştirme formu"""
    if not request.user.is_authenticated:
        return redirect('accounts:login')
    
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        
        if form.is_valid():
            form.save()
            
            # Update session to keep user logged in after password change
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, request.user)
            
            messages.success(request, 'Şifreniz başarıyla değiştirildi.')
            return redirect('accounts:profile')
        
        return render(request, 'accounts/password_change.html', {
            'errors': form.errors
        })
    
    return render(request, 'accounts/password_change.html')