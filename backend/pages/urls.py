from django.urls import path
from . import views

app_name = 'pages'

urlpatterns = [
    path('pages/', views.page_list, name='list'),
    path('pages/tree/', views.page_tree, name='tree'),
    path('pages/search/', views.search_pages, name='search'),
    path('<slug:slug>/', views.page_detail, name='detail'),
]
