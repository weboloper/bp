from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PostViewSet

# Create router and register viewsets
router = DefaultRouter()
router.register(r'', PostViewSet, basename='post')

app_name = 'posts_api'

# URL patterns
urlpatterns = [
    path('', include(router.urls)),
]
