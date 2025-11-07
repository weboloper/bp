from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PageViewSet

# Create router and register viewsets
router = DefaultRouter()
router.register(r'', PageViewSet, basename='page')

app_name = 'pages_api'

# URL patterns
urlpatterns = [
    path('', include(router.urls)),
]
