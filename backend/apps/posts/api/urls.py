from django.urls import path
from .views import (
    PostListAPIView,
    PostDetailAPIView,
    PostCreateAPIView,
    MyPostsAPIView,
    PostUpdateAPIView,
    PostDeleteAPIView,
    TestPublicAPIView,
    TestPrivateAPIView,
)

app_name = 'posts_api'

urlpatterns = [
    # Public endpoints
    path('', PostListAPIView.as_view(), name='list'),
    path('<int:pk>/', PostDetailAPIView.as_view(), name='detail'),
    
    # Authenticated endpoints
    path('create/', PostCreateAPIView.as_view(), name='create'),
    path('my/', MyPostsAPIView.as_view(), name='my_posts'),
    
    # Owner-only endpoints
    path('<int:pk>/update/', PostUpdateAPIView.as_view(), name='update'),
    path('<int:pk>/delete/', PostDeleteAPIView.as_view(), name='delete'),
    
    # Test endpoints
    path('test/public/', TestPublicAPIView.as_view(), name='test_public'),
    path('test/private/', TestPrivateAPIView.as_view(), name='test_private'),
]
