from django.urls import path
from .views import (
    PageListCreateAPIView,
    PageDetailAPIView,
    PageSlugDetailAPIView,
    PageTreeAPIView
)

app_name = 'pages_api'

urlpatterns = [
    # Liste ve oluşturma
    path('', PageListCreateAPIView.as_view(), name='page_list_create'),
    
    # Özel endpoint'ler
    path('tree/', PageTreeAPIView.as_view(), name='page_tree'),
    
    # Slug ile detay (SEO friendly - public)
    path('slug/<slug:slug>/', PageSlugDetailAPIView.as_view(), name='page_slug_detail'),
    
    # ID ile CRUD işlemleri (Primary - güvenli)
    path('<int:pk>/', PageDetailAPIView.as_view(), name='page_detail'),
]
