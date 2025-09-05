"""
Core application views
Basic views for health checks and general pages
"""
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.conf import settings
from django.utils import timezone
import sys
import platform


def health_check(request):
    """
    Health check endpoint for monitoring
    Returns system status and basic info
    """
    health_data = {
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
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
    context = {
        'title': 'BP Django-Caddy Application',
        'environment': getattr(settings, 'CURRENT_ENV', 'development'),
        'debug': settings.DEBUG,
        'timestamp': timezone.now(),
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
    api_info = {
        'message': 'BP Django-Caddy API',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health/',
            'admin': '/admin/',
            'auth': '/auth/',
        },
        'timestamp': timezone.now().isoformat(),
    }
    
    return JsonResponse(api_info)
