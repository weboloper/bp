from django.shortcuts import render
from django.http import Http404
from .models import Page


def custom_404_handler(request, exception):
    """
    Custom 404 handler - sayfa bulunamazsa benzer sayfalar öner
    """
    requested_path = request.path.strip('/')
    
    # Benzer slug'ları ara
    similar_pages = Page.objects.filter(
        is_published=True,
        slug__icontains=requested_path[:10]  # İlk 10 karakter
    )[:5]
    
    # Eğer benzer sayfa yoksa, popüler sayfaları göster
    if not similar_pages:
        similar_pages = Page.objects.filter(
            is_published=True,
            parent=None
        ).order_by('order', 'title')[:5]
    
    context = {
        'requested_path': f'/{requested_path}/',
        'similar_pages': similar_pages,
        'page_title': 'Sayfa Bulunamadı'
    }
    
    return render(request, 'pages/404.html', context, status=404)
