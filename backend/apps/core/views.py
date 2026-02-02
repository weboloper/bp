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
from notifications.services import send_template_email, send_sms
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
    Email test page - notifications.services.send_template_email test
    Tests both sync and async email sending modes
    """
    if request.method == 'POST':
        email_type = request.POST.get('email_type')
        recipient_email = request.POST.get('recipient_email', '').strip()
        template_name = request.POST.get('template_name', '').strip()

        # Manual template override
        manual_template = request.POST.get('template_name_manual', '').strip()
        if manual_template:
            template_name = manual_template

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
            'verification_link': f'{settings.FRONTEND_URL}/test-link/',
            'reset_link': f'{settings.FRONTEND_URL}/test-reset/',
        }

        try:
            if email_type == 'async':
                send_template_email(
                    to=recipient_email,
                    subject=f'Test Email (Async) - {template_name}',
                    template_name=template_name,
                    context=test_context,
                    sync=False
                )
                celery_enabled = getattr(settings, 'CELERY_ENABLED', False)
                if celery_enabled:
                    messages.success(request, f'Async email Celery queue\'ya eklendi: {recipient_email}')
                else:
                    messages.success(request, f'Email gönderildi (Celery kapalı, sync fallback): {recipient_email}')

            elif email_type == 'sync':
                send_template_email(
                    to=recipient_email,
                    subject=f'Test Email (Sync) - {template_name}',
                    template_name=template_name,
                    context=test_context,
                    sync=True
                )
                messages.success(request, f'Sync email başarıyla gönderildi: {recipient_email}')

        except Exception as e:
            messages.error(request, f'Email gönderimi başarısız: {str(e)}')

        return redirect('test_email')

    # GET request - show test form
    context = {
        'available_templates': [
            'accounts/emails/welcome',
            'accounts/emails/email_verification',
            'accounts/emails/password_reset',
        ],
        'frontend_url': settings.FRONTEND_URL,
        'current_env': getattr(settings, 'CURRENT_ENV', 'development'),
        'celery_enabled': getattr(settings, 'CELERY_ENABLED', False),
        'email_provider': getattr(settings, 'EMAIL_PROVIDER', 'smtp'),
        'sms_provider': getattr(settings, 'SMS_PROVIDER', 'mock'),
        'email_backend': settings.EMAIL_BACKEND,
        'email_host': getattr(settings, 'EMAIL_HOST', 'Not configured'),
        'email_host_user': getattr(settings, 'EMAIL_HOST_USER', 'Not configured'),
    }

    return render(request, 'core/test_email.html', context)


def test_sms(request):
    """
    SMS test page - notifications.services.send_sms test
    Tests both sync and async SMS sending modes
    """
    if request.method == 'POST':
        sms_type = request.POST.get('sms_type')
        recipient_phone = request.POST.get('recipient_phone', '').strip()
        message = request.POST.get('message', '').strip()

        # Basic validation
        if not recipient_phone:
            messages.error(request, 'Telefon numarasi gerekli')
            return redirect('test_sms')

        if not message:
            messages.error(request, 'Mesaj gerekli')
            return redirect('test_sms')

        try:
            if sms_type == 'async':
                send_sms(
                    to=recipient_phone,
                    message=message,
                    sync=False
                )
                celery_enabled = getattr(settings, 'CELERY_ENABLED', False)
                if celery_enabled:
                    messages.success(request, f'Async SMS Celery queue\'ya eklendi: {recipient_phone}')
                else:
                    messages.success(request, f'SMS gonderildi (Celery kapali, sync fallback): {recipient_phone}')

            elif sms_type == 'sync':
                send_sms(
                    to=recipient_phone,
                    message=message,
                    sync=True
                )
                messages.success(request, f'Sync SMS basariyla gonderildi: {recipient_phone}')

        except Exception as e:
            messages.error(request, f'SMS gonderimi basarisiz: {str(e)}')

        return redirect('test_sms')

    # GET request - show test form
    sms_provider = getattr(settings, 'SMS_PROVIDER', 'mock')

    # Provider-specific config info
    provider_config = {}
    if sms_provider == 'netgsm':
        provider_config = {
            'username': getattr(settings, 'NETGSM_USERNAME', ''),
            'header': getattr(settings, 'NETGSM_HEADER', ''),
        }
    elif sms_provider == 'twilio':
        provider_config = {
            'account_sid': getattr(settings, 'TWILIO_ACCOUNT_SID', '')[:10] + '...' if getattr(settings, 'TWILIO_ACCOUNT_SID', '') else '',
            'from_number': getattr(settings, 'TWILIO_FROM_NUMBER', ''),
        }

    context = {
        'frontend_url': settings.FRONTEND_URL,
        'current_env': getattr(settings, 'CURRENT_ENV', 'development'),
        'celery_enabled': getattr(settings, 'CELERY_ENABLED', False),
        'sms_provider': sms_provider,
        'provider_config': provider_config,
        'sample_messages': [
            'Merhaba! Bu bir test SMS mesajidir.',
            'Dogrulama kodunuz: 123456',
            'Randevunuz 15 Ocak 2025 saat 14:00\'da onaylandi.',
        ],
    }

    return render(request, 'core/test_sms.html', context)
