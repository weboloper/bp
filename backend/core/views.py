"""
Core application views
Basic views for health checks and general pages
"""
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from django.utils import timezone
from core.utils import DateUtils
from core.email_service import EmailService
import sys
import platform


def health_check(request):
    """
    Health check endpoint for monitoring
    Returns system status and basic info
    """
    local_time = DateUtils.get_local_time()
    
    health_data = {
        'status': 'healthy',
        'timestamp': local_time.isoformat(),
        'timezone': settings.TIME_ZONE,
        'environment': getattr(settings, 'CURRENT_ENV', 'unknown'),
        'debug': settings.DEBUG,
        'python_version': platform.python_version(),
        'django_version': '5.2.5',  # Django version
    }
    
    return JsonResponse(health_data)


def home(request):
    """
    Home page view
    Simple welcome page for the application
    """
    local_time = DateUtils.get_local_time()
    
    context = {
        'title': 'BP Django-Caddy Application',
        'environment': getattr(settings, 'CURRENT_ENV', 'development'),
        'static_handler': getattr(settings, 'STATIC_FILES_HANDLER', '--'),
        'debug': settings.DEBUG,
        'timestamp': local_time,
    }
    
    # If it's an API request or JSON is preferred
    if request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
        return JsonResponse({
            'message': 'Welcome to BP Django-Caddy Application',
            'status': 'active',
            **context
        })

    return render(request, 'core/home.html', context )


def api_root(request):
    """
    API root endpoint - Basit yapı
    Mevcut endpoint'leri listeler
    """
    api_info = {
        'message': 'BP Django API',
        'version': '1.0.0',
        'timestamp': timezone.now().isoformat(),
        'available_endpoints': {
            'accounts': {
                'login': '/api/accounts/auth/login/',
                'token_refresh': '/api/accounts/auth/token/refresh/',
                'token_verify': '/api/accounts/auth/token/verify/',
            },
            'system': {
                'health': '/health/',
                'admin': '/admin/',
            }
        },
        'note': 'Simple and clean API structure'
    }
    
    return JsonResponse(api_info)


def test_email(request):
    """
    Email test page - send_smart_email and send_critical_email test
    """
    if request.method == 'POST':
        email_type = request.POST.get('email_type')
        recipient_email = request.POST.get('recipient_email', '').strip()
        template_name = request.POST.get('template_name', '').strip()
        
        # Basic validation
        if not recipient_email:
            messages.error(request, 'Email adresi gerekli')
            return redirect('test_email')
        
        if not template_name:
            messages.error(request, 'Template adı gerekli')
            return redirect('test_email')
        
        # Test context data
        test_context = {
            'user': {
                'username': 'test_user',
                'email': recipient_email,
                'first_name': 'Test',
                'created_at': timezone.now()
            },
            'site_url': settings.FRONTEND_URL,
            'test_data': 'Bu bir test emailidir',
        }
        
        try:
            if email_type == 'smart':
                EmailService.send_smart_email(
                    template_name=template_name,
                    context=test_context,
                    subject=f'Test Email (Smart) - {template_name}',
                    recipient_list=[recipient_email]
                )
                messages.success(request, f'Smart email başarıyla gönderildi: {recipient_email}')
            
            elif email_type == 'critical':
                EmailService.send_critical_email(
                    template_name=template_name,
                    context=test_context,
                    subject=f'Test Email (Critical) - {template_name}',
                    recipient_list=[recipient_email]
                )
                messages.success(request, f'Critical email başarıyla gönderildi: {recipient_email}')
                
        except Exception as e:
            messages.error(request, f'Email gönderimi başarısız: {str(e)}')
        
        return redirect('test_email')
    
    # GET request - show test form
    context = {
        'available_templates': [
            'accounts/emails/welcome',
            'accounts/emails/verification',
            'accounts/emails/password_reset',
        ],
        'frontend_url': settings.FRONTEND_URL,
        'current_env': getattr(settings, 'CURRENT_ENV', 'development'),
        'use_async_email': getattr(settings, 'USE_ASYNC_EMAIL', False),
        'email_backend': settings.EMAIL_BACKEND,
        'email_host': getattr(settings, 'EMAIL_HOST', 'Not configured'),
        'email_host_user': getattr(settings, 'EMAIL_HOST_USER', 'Not configured'),
    }
    
    return render(request, 'core/test_email.html', context)
