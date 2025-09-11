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
    
    # Return simple HTML response for now
    html_content = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{context['title']}</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #f8f9fa;
                color: #343a40;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .status {{
                background: #d4edda;
                color: #155724;
                padding: 10px 15px;
                border-radius: 4px;
                margin: 20px 0;
            }}
            .info {{
                background: #d1ecf1;
                color: #0c5460;
                padding: 10px 15px;
                border-radius: 4px;
                margin: 10px 0;
            }}
            .links {{
                margin-top: 30px;
            }}
            .links a {{
                display: inline-block;
                margin: 5px 10px;
                padding: 8px 16px;
                background: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 4px;
            }}
            .links a:hover {{
                background: #0056b3;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚀 {context['title']}</h1>
                <p>Django-Caddy uygulaması başarıyla çalışıyor!</p>
            </div>
            
            <div class="status">
                ✅ Sistem aktif ve çalışır durumda
            </div>
            
            <div class="info">
                <strong>Ortam:</strong> {context['environment'].title()}<br>
                <strong>Debug Modu:</strong> {'Açık' if context['debug'] else 'Kapalı'}<br>
                <strong>Zaman:</strong> {context['timestamp'].strftime('%d.%m.%Y %H:%M:%S')}
            </div>
            
            <div class="links">
                <h3>🔗 Linkler:</h3>
                <a href="/admin/">🔧 Admin Panel</a>
                <a href="/health/">💚 Health Check</a>
                <a href="/api/">📡 API Docs</a>
            </div>
            
            <div style="margin-top: 30px; text-align: center; color: #6c757d; font-size: 14px;">
                <p>BP Django-Caddy Stack • VPS Deployment</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HttpResponse(html_content)


def api_root(request):
    """
    API root endpoint
    Lists available API endpoints
    """
    local_time = DateUtils.get_local_time()
    
    api_info = {
        'message': 'BP Django-Caddy API',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health/',
            'admin': '/admin/',
            'auth': '/auth/',
        },
        'timestamp': local_time.isoformat(),
        'timezone': settings.TIME_ZONE,
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
