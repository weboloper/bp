"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core.views import home, health_check, api_root

urlpatterns = [
    # Admin panel
    path('admin/', admin.site.urls),
    
    # Core endpoints
    path('', home, name='home'),
    path('health/', health_check, name='health_check'),
    path('api/', api_root, name='api_root'),
    
    # App URLs
    path('accounts/', include('accounts.urls')),
    
    # API endpoints (add your app URLs here)
    # path('api/v1/', include('your_app.urls')),
]

# Media dosyalar sadece development'ta Django'dan serve edilir
# Static dosyalar artık Caddy tarafından serve ediliyor
if settings.DEBUG and settings.STATIC_FILES_HANDLER not in ['caddy', 'nginx']:
    # Sadece whitenoise gibi handler'lar için media files - static files Caddy/Nginx'den gelir
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
