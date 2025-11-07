from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

from posts.models import Post
from .serializers import (
    PostBasicSerializer,
    PostSerializer,
    PostDetailSerializer
)
from .permissions import IsOwnerOrReadOnly


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='list')
@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='retrieve')
@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method=['POST', 'PUT', 'PATCH', 'DELETE']), name='dispatch')
class PostViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Post model.
    Provides CRUD operations for posts.

    List/Retrieve: AllowAny (published posts only)
    Create: IsAuthenticated
    Update/Delete: IsOwnerOrReadOnly (owner only)

    Endpoints:
    - GET    /api/posts/              - Liste (published only)
    - POST   /api/posts/              - Yeni post oluştur (authenticated)
    - GET    /api/posts/{id}/         - Detay (published only)
    - PUT    /api/posts/{id}/         - Güncelle (owner only)
    - PATCH  /api/posts/{id}/         - Kısmi güncelle (owner only)
    - DELETE /api/posts/{id}/         - Sil (owner only)
    - GET    /api/posts/my/           - Kullanıcının kendi postları
    """
    queryset = Post.objects.all()
    permission_classes = [IsOwnerOrReadOnly]

    def get_permissions(self):
        """
        List ve Retrieve için AllowAny, Create için IsAuthenticated,
        Update/Delete için IsOwnerOrReadOnly.
        """
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        elif self.action == 'create':
            return [IsAuthenticated()]
        elif self.action == 'my_posts':
            return [IsAuthenticated()]
        return [IsOwnerOrReadOnly()]

    def get_serializer_class(self):
        """Action'a göre uygun serializer döndür"""
        if self.action == 'retrieve':
            return PostDetailSerializer
        return PostSerializer

    def get_queryset(self):
        """
        Filter queryset and optimize queries.

        Query Parameters:
        - author: Author ID'ye göre filtrele (ör: ?author=1)
        - search: Başlık veya içeriğe göre ara (ör: ?search=django)
        """
        user = self.request.user

        # Admin veya owner kendi unpublished postlarını da görebilir
        if user.is_staff or user.is_superuser:
            queryset = Post.objects.all()
        elif user.is_authenticated and self.action == 'my_posts':
            # Kullanıcının kendi tüm postları (published + unpublished)
            queryset = Post.objects.filter(author=user)
        else:
            # Normal kullanıcılar için sadece yayınlanmış postlar
            queryset = Post.objects.filter(is_published=True)

        # Query optimization
        queryset = queryset.select_related('author')

        # Author filtreleme
        author_id = self.request.query_params.get('author')
        if author_id:
            try:
                queryset = queryset.filter(author_id=int(author_id))
            except (ValueError, TypeError):
                pass  # Invalid author_id, ignore

        # Arama
        search_query = self.request.query_params.get('search')
        if search_query:
            queryset = queryset.filter(title__icontains=search_query) | queryset.filter(content__icontains=search_query)

        return queryset.order_by('-created_at')

    def create(self, request, *args, **kwargs):
        """
        Yeni post oluştur (Authenticated users only).

        POST /api/posts/
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            try:
                # Author'ı mevcut kullanıcı olarak set et
                post = serializer.save(author=request.user)

                # Return created post data with detail serializer
                response_serializer = PostDetailSerializer(post, context={'request': request})
                return Response(
                    response_serializer.data,
                    status=status.HTTP_201_CREATED
                )

            except Exception as e:
                return Response(
                    {'detail': f'Post oluşturulurken bir hata oluştu: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """
        Post güncelle - tüm alanlar (Owner only).

        PUT /api/posts/{id}/
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Permission check (IsOwnerOrReadOnly handles this, but double check)
        if instance.author != request.user and not request.user.is_staff:
            return Response(
                {'detail': 'Bu post\'u güncelleme yetkiniz yok'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        if serializer.is_valid():
            try:
                post = serializer.save()

                # Return updated post data with detail serializer
                response_serializer = PostDetailSerializer(post, context={'request': request})
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )

            except Exception as e:
                return Response(
                    {'detail': f'Post güncellenirken bir hata oluştu: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        """
        Post kısmi güncelle - sadece gönderilen alanlar (Owner only).

        PATCH /api/posts/{id}/
        """
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Post sil (Owner only).

        DELETE /api/posts/{id}/
        """
        instance = self.get_object()

        # Permission check (IsOwnerOrReadOnly handles this, but double check)
        if instance.author != request.user and not request.user.is_staff:
            return Response(
                {'detail': 'Bu post\'u silme yetkiniz yok'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            post_title = instance.title
            instance.delete()

            return Response(
                {'detail': f'"{post_title}" başlıklı post başarıyla silindi'},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {'detail': f'Post silinirken bir hata oluştu: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # ========================================================================
    # Custom Actions
    # ========================================================================

    @action(detail=False, methods=['get'], url_path='my')
    def my_posts(self, request):
        """
        Kullanıcının kendi postlarını döndürür (published + unpublished).

        GET /api/posts/my/

        Returns:
            200: Kullanıcının tüm postları
        """
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
