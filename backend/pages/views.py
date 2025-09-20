from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import Page


def page_list(request):
    """
    Sayfaları listeler (sadece üst seviye sayfalar)
    """
    pages = Page.objects.filter(is_published=True, parent=None).order_by('order', 'title')
    
    context = {
        'pages': pages,
        'page_title': 'Sayfalar',
    }
    
    return render(request, 'pages/page_list.html', context)


def page_detail(request, slug):
    """
    Sayfa detayını gösterir
    """
    page = get_object_or_404(Page, slug=slug, is_published=True)
    
    # Alt sayfaları al
    children = page.get_children()
    
    # Breadcrumb için üst sayfaları al
    breadcrumbs = page.get_breadcrumbs()
    
    context = {
        'page': page,
        'children': children,
        'breadcrumbs': breadcrumbs,
        'page_title': page.title,
    }
    
    return render(request, 'pages/page_detail.html', context)


def page_tree(request):
    """
    Tüm sayfaların hiyerarşik görünümü
    """
    # Ana sayfaları al (parent=None)
    root_pages = Page.objects.filter(is_published=True, parent=None).order_by('order', 'title')
    
    def get_page_tree_data(pages, level=0):
        """Recursive function to build page tree"""
        tree_data = []
        for page in pages:
            children = page.get_children()
            tree_data.append({
                'page': page,
                'level': level,
                'children': get_page_tree_data(children, level + 1) if children else []
            })
        return tree_data
    
    tree_data = get_page_tree_data(root_pages)
    
    context = {
        'tree_data': tree_data,
        'page_title': 'Sayfa Ağacı',
    }
    
    return render(request, 'pages/page_tree.html', context)


def search_pages(request):
    """
    Sayfalarda arama yapar
    """
    query = request.GET.get('q', '').strip()
    results = []
    
    if query:
        results = Page.objects.filter(
            is_published=True
        ).filter(
            title__icontains=query
        ) | Page.objects.filter(
            is_published=True,
            content__icontains=query
        ).distinct().order_by('order', 'title')
    
    context = {
        'query': query,
        'results': results,
        'result_count': len(results),
        'page_title': f'Arama: {query}' if query else 'Sayfa Arama',
    }
    
    return render(request, 'pages/search.html', context)
