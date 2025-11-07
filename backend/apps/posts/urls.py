from django.urls import path, include
from . import views

app_name = 'posts'

urlpatterns = [
    # Normal HTML views
    path('', views.post_list, name='post_list'),
    path('<int:pk>/', views.post_detail, name='post_detail'),
    path('my/', views.my_posts, name='my_posts'),
    path('create/', views.post_create, name='post_create'),
    path('<int:pk>/update/', views.post_update, name='post_update'),
    path('<int:pk>/delete/', views.post_delete, name='post_delete'),
]
