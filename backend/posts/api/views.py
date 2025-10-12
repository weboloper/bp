from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

from posts.models import Post
from .serializers import (
    PostListSerializer,
    PostDetailSerializer,
    PostCreateUpdateSerializer
)
from .permissions import IsOwnerOrReadOnly


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
class PostListAPIView(APIView):
    """
    Tüm yayınlanmış postları listele
    GET: Public access (AllowAny)
    
    Query Parameters:
    - author: Author ID'ye göre filtrele (ör: ?author=1)
    - search: Başlık veya içeriğe göre ara (ör: ?search=django)
    
    Rate limit: 60 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        queryset = Post.objects.filter(is_published=True).select_related('author')
        
        # Author filtreleme
        author_id = request.query_params.get('author')
        if author_id:
            try:
                queryset = queryset.filter(author_id=int(author_id))
            except (ValueError, TypeError):
                return Response(
                    {'detail': 'Geçersiz author parametresi'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Arama
        search_query = request.query_params.get('search')
        if search_query:
            queryset = queryset.filter(
                title__icontains=search_query
            ) | queryset.filter(
                content__icontains=search_query
            )
        
        # Sıralama
        queryset = queryset.order_by('-created_at')
        
        serializer = PostListSerializer(
            queryset, 
            many=True,
            context={'request': request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
class PostDetailAPIView(APIView):
    """
    Post detayını getir (ID ile)
    GET: Public access (AllowAny)
    
    Rate limit: 60 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def get(self, request, pk):
        post = get_object_or_404(Post, pk=pk, is_published=True)
        serializer = PostDetailSerializer(post, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method='POST'), name='post')
class PostCreateAPIView(APIView):
    """
    Yeni post oluştur
    POST: Requires authentication (IsAuthenticated)
    
    Rate limit: 30 requests per hour per user or IP
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = PostCreateUpdateSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                post = serializer.save(author=request.user)
                
                # Return created post data
                response_serializer = PostDetailSerializer(post, context={'request': request})
                return Response(
                    response_serializer.data,
                    status=status.HTTP_201_CREATED
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Post oluşturulurken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='user', rate='60/m', method='GET'), name='get')
class MyPostsAPIView(APIView):
    """
    Kullanıcının kendi postlarını listele
    GET: Requires authentication (IsAuthenticated)
    
    Hem yayınlanmış hem yayınlanmamış postları gösterir
    
    Rate limit: 60 requests per minute per user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        posts = Post.objects.filter(author=request.user).order_by('-created_at')
        serializer = PostListSerializer(posts, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method=['PUT', 'PATCH']), name='dispatch')
class PostUpdateAPIView(APIView):
    """
    Post güncelle
    PUT/PATCH: Owner only (IsAuthenticated + IsOwnerOrReadOnly)
    
    Rate limit: 30 requests per hour per user or IP
    """
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_object(self, pk):
        """Get post and check ownership via permission class"""
        post = get_object_or_404(Post, pk=pk)
        
        # Check object-level permission
        for permission in self.permission_classes:
            permission_instance = permission()
            if hasattr(permission_instance, 'has_object_permission'):
                if not permission_instance.has_object_permission(self.request, self, post):
                    from rest_framework.exceptions import PermissionDenied
                    raise PermissionDenied('Bu postu düzenleme yetkiniz yok')
        
        return post
    
    def put(self, request, pk):
        """Full update - all fields required"""
        post = self.get_object(pk)
        serializer = PostCreateUpdateSerializer(post, data=request.data)
        
        if serializer.is_valid():
            try:
                post = serializer.save()
                
                # Return updated post data
                response_serializer = PostDetailSerializer(post, context={'request': request})
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Post güncellenirken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """Partial update - only provided fields"""
        post = self.get_object(pk)
        serializer = PostCreateUpdateSerializer(post, data=request.data, partial=True)
        
        if serializer.is_valid():
            try:
                post = serializer.save()
                
                # Return updated post data
                response_serializer = PostDetailSerializer(post, context={'request': request})
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Post güncellenirken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method='DELETE'), name='delete')
class PostDeleteAPIView(APIView):
    """
    Post sil
    DELETE: Owner only (IsAuthenticated + IsOwnerOrReadOnly)
    
    Rate limit: 30 requests per hour per user or IP
    """
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_object(self, pk):
        """Get post and check ownership via permission class"""
        post = get_object_or_404(Post, pk=pk)
        
        # Check object-level permission
        for permission in self.permission_classes:
            permission_instance = permission()
            if hasattr(permission_instance, 'has_object_permission'):
                if not permission_instance.has_object_permission(self.request, self, post):
                    from rest_framework.exceptions import PermissionDenied
                    raise PermissionDenied('Bu postu silme yetkiniz yok')
        
        return post
    
    def delete(self, request, pk):
        post = self.get_object(pk)
        
        try:
            post_title = post.title
            post.delete()
            
            return Response(
                {'detail': f'"{post_title}" başarıyla silindi'},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'detail': 'Post silinirken bir hata oluştu'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ============================================
# TEST ENDPOINTS
# ============================================

@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
class TestPublicAPIView(APIView):
    """
    Test endpoint - Public access
    GET: Anyone can access
    
    Rate limit: 60 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        data = {
            'message': 'This is a public endpoint',
            'authenticated': request.user.is_authenticated,
        }
        if request.user.is_authenticated:
            data['username'] = request.user.username
            data['user_id'] = request.user.id
        
        return Response(data, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key='user', rate='60/m', method='GET'), name='get')
class TestPrivateAPIView(APIView):
    """
    Test endpoint - Requires authentication
    GET: Only authenticated users
    
    Rate limit: 60 requests per minute per user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'message': f'Hello {request.user.username}!',
            'user_id': request.user.id,
            'email': request.user.email,
        }, status=status.HTTP_200_OK)
