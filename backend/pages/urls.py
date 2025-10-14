from django.urls import path
from . import views

app_name = 'pages'

urlpatterns = [
    path('pages/', views.page_list, name='page_list'),
    path('pages/tree/', views.page_tree, name='page_tree'),
    path('pages/search/', views.search_pages, name='page_search'),
    path('<slug:slug>/', views.page_detail, name='page_detail'),
]
