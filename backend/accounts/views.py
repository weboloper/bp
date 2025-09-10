from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login
from django.conf import settings
from accounts.models import User
from accounts.utils import validate_alphanumeric_username
from core.email_service import EmailService
from django.core.exceptions import ValidationError

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
                
        # Email validation
        if not email:
            errors['email'] = 'Email gerekli'
        elif len(email) > 254:
            errors['email'] = 'Email çok uzun'
        elif '@' not in email or '.' not in email:
            errors['email'] = 'Geçerli bir email adresi giriniz'
        elif User.objects.filter(email=email).exists():
            errors['email'] = 'Bu email adresi zaten kayıtlı'
            
        # Password validation
        if not password1:
            errors['password1'] = 'Şifre gerekli'
        elif len(password1) < 8:
            errors['password1'] = 'Şifre en az 8 karakter olmalı'
        elif len(password1) > 128:
            errors['password1'] = 'Şifre çok uzun'
            
        if not password2:
            errors['password2'] = 'Şifre tekrarı gerekli'
        elif password1 != password2:
            errors['password2'] = 'Şifreler eşleşmiyor'
            
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
                return redirect('login')
                    
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
        # Login logic will be implemented later
        pass
    return render(request, 'accounts/login.html')

def profile_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    return render(request, 'accounts/profile.html', {
        'user': request.user,
        'profile': request.user.profile
    })
