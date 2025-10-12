from django.urls import path, include
from . import views

app_name = 'posts'

urlpatterns = [
    # Normal HTML views
    path('', views.post_list, name='list'),
    path('<int:pk>/', views.post_detail, name='detail'),
    path('my/', views.my_posts, name='my_posts'),
    path('create/', views.post_create, name='create'),
    path('<int:pk>/update/', views.post_update, name='update'),
    path('<int:pk>/delete/', views.post_delete, name='delete'),
    
    # API endpoints
    path('api/', include('posts.api.urls')),
]
