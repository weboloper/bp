from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Post


def post_list(request):
    """
    Tüm yayınlanmış postları listeler (public)
    """
    posts = Post.objects.filter(is_published=True).select_related('author').order_by('-created_at')
    
    context = {
        'posts': posts,
        'page_title': 'Tüm Postlar',
    }
    
    return render(request, 'posts/post_list.html', context)


def post_detail(request, pk):
    """
    Post detayını gösterir (public)
    """
    post = get_object_or_404(Post, pk=pk, is_published=True)
    
    # Yorumları al (eğer varsa)
    comments = post.comments.select_related('author').order_by('created_at')
    
    context = {
        'post': post,
        'comments': comments,
        'page_title': post.title,
        'is_owner': request.user.is_authenticated and post.author == request.user,
    }
    
    return render(request, 'posts/post_detail.html', context)


@login_required
def my_posts(request):
    """
    Kullanıcının kendi postlarını listeler (authenticated)
    Hem yayınlanmış hem yayınlanmamış postları gösterir
    """
    posts = Post.objects.filter(author=request.user).order_by('-created_at')
    
    context = {
        'posts': posts,
        'page_title': 'Postlarım',
    }
    
    return render(request, 'posts/my_posts.html', context)


@login_required
def post_create(request):
    """
    Yeni post oluştur (authenticated)
    """
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        content = request.POST.get('content', '').strip()
        is_published = request.POST.get('is_published', 'true') == 'true'
        
        if not title or not content:
            messages.error(request, 'Başlık ve içerik gereklidir')
        else:
            try:
                post = Post.objects.create(
                    author=request.user,
                    title=title,
                    content=content,
                    is_published=is_published
                )
                messages.success(request, 'Post başarıyla oluşturuldu')
                return redirect('posts:detail', pk=post.pk)
            except Exception as e:
                messages.error(request, 'Post oluşturulurken bir hata oluştu')
    
    context = {
        'page_title': 'Yeni Post Oluştur',
    }
    
    return render(request, 'posts/post_create.html', context)


@login_required
def post_update(request, pk):
    """
    Post güncelle (only owner)
    """
    post = get_object_or_404(Post, pk=pk, author=request.user)
    
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        content = request.POST.get('content', '').strip()
        is_published = request.POST.get('is_published', 'true') == 'true'
        
        if not title or not content:
            messages.error(request, 'Başlık ve içerik gereklidir')
        else:
            try:
                post.title = title
                post.content = content
                post.is_published = is_published
                post.save()
                
                messages.success(request, 'Post başarıyla güncellendi')
                return redirect('posts:detail', pk=post.pk)
            except Exception as e:
                messages.error(request, 'Post güncellenirken bir hata oluştu')
    
    context = {
        'post': post,
        'page_title': f'Düzenle: {post.title}',
    }
    
    return render(request, 'posts/post_update.html', context)


@login_required
def post_delete(request, pk):
    """
    Post sil (only owner)
    """
    post = get_object_or_404(Post, pk=pk, author=request.user)
    
    if request.method == 'POST':
        try:
            post_title = post.title
            post.delete()
            messages.success(request, f'"{post_title}" başarıyla silindi')
            return redirect('posts:my_posts')
        except Exception as e:
            messages.error(request, 'Post silinirken bir hata oluştu')
    
    context = {
        'post': post,
        'page_title': f'Sil: {post.title}',
    }
    
    return render(request, 'posts/post_delete.html', context)
