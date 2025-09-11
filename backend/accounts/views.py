from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.conf import settings
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from accounts.models import User
from accounts.utils import validate_alphanumeric_username
from core.email_service import EmailService
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

def register_view(request):
    if request.method == 'POST':
        errors = {}
        
        # Form data
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        
        # Username validation
        if not username:
            errors['username'] = 'Kullanıcı adı gerekli'
        elif len(username) < 3:
            errors['username'] = 'Kullanıcı adı en az 3 karakter olmalı'
        elif len(username) > 30:
            errors['username'] = 'Kullanıcı adı en fazla 30 karakter olabilir'
        else:
            try:
                validate_alphanumeric_username(username)
            except ValidationError as e:
                errors['username'] = str(e.message)
            
            # Check if username exists
            if User.objects.filter(username=username).exists():
                errors['username'] = 'Bu kullanıcı adı zaten alınmış'
                
        # Email validation using Django's built-in validator
        if not email:
            errors['email'] = 'Email gerekli'
        else:
            try:
                validate_email(email)
            except ValidationError:
                errors['email'] = 'Geçerli bir email adresi giriniz'
            
            # Check if email exists
            if User.objects.filter(email=email).exists():
                errors['email'] = 'Bu email adresi zaten kayıtlı'
            
        # Password confirmation validation
        if not password1:
            errors['password1'] = 'Şifre gerekli'
        
        if not password2:
            errors['password2'] = 'Şifre tekrarı gerekli'
        elif password1 != password2:
            errors['password2'] = 'Şifreler eşleşmiyor'
            
        # Password validation using Django's built-in validators
        if password1:
            try:
                validate_password(password1)
            except ValidationError as e:
                errors['password1'] = ' '.join(e.messages)
            
        # If no errors, create user
        if not errors:
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1
                )
                
                # Send welcome email
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
                    # Log error but don't fail registration
                    print(f"Welcome email failed: {e}")
                
                messages.success(request, 'Kayıt başarılı! Hoş geldin emaili gönderildi.')
                # return redirect('accounts:login')
                return render(request, 'accounts/register.html')
                    
            except Exception as e:
                messages.error(request, 'Kayıt sırasında bir hata oluştu')
        
        # Return errors
        return render(request, 'accounts/register.html', {
            'errors': errors,
            'username': username,
            'email': email
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
        errors = {}
        email = request.POST.get('email', '').strip()
        
        # Email validation
        if not email:
            errors['email'] = 'Email adresi gerekli'
        else:
            try:
                validate_email(email)
            except ValidationError:
                errors['email'] = 'Geçerli bir email adresi giriniz'
        
        if not errors:
            try:
                user = User.objects.get(email=email)
                
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
                    errors['email'] = 'Email gönderimi başarısız. Lütfen tekrar deneyin.'
                    
            except User.DoesNotExist:
                # Security: Don't reveal if email exists
                messages.success(request, 'Şifre sıfırlama linki email adresinize gönderildi.')
                return redirect('home')
        
        return render(request, 'accounts/password_reset.html', {
            'errors': errors,
            'email': email
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
            errors = {}
            password1 = request.POST.get('password1', '')
            password2 = request.POST.get('password2', '')
            
            # Password validation
            if not password1:
                errors['password1'] = 'Yeni şifre gerekli'
            
            if not password2:
                errors['password2'] = 'Şifre tekrarı gerekli'
            elif password1 != password2:
                errors['password2'] = 'Şifreler eşleşmiyor'
            
            # Django password validation
            if password1:
                try:
                    validate_password(password1, user)
                except ValidationError as e:
                    errors['password1'] = ' '.join(e.messages)
            
            if not errors:
                # Set new password
                user.set_password(password1)
                user.save()
                
                messages.success(request, 'Şifreniz başarıyla değiştirildi. Yeni şifrenizle giriş yapabilirsiniz.')
                return redirect('accounts:login')
            
            return render(request, 'accounts/password_reset_confirm.html', {
                'errors': errors,
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