from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

from pages.models import Page
from .serializers import (
    PageListSerializer,
    PageDetailSerializer,
    PageCreateUpdateSerializer
)


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method='POST'), name='post')
class PageListCreateAPIView(APIView):
    """
    Sayfa listesi ve oluşturma endpoint
    GET: Tüm yayınlanmış sayfaları listeler (AllowAny)
    POST: Yeni sayfa oluştur (IsAdminUser)
    """
    
    def get_permissions(self):
        """GET için AllowAny, POST için IsAdminUser"""
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [AllowAny()]
    
    def get(self, request):
        """
        Tüm yayınlanmış sayfaları listele
        
        Query Parameters:
        - parent: Parent ID'ye göre filtrele (ör: ?parent=1 veya ?parent=null)
        - search: Başlık veya içeriğe göre ara (ör: ?search=hakkımızda)
        
        Rate limit: 60 requests per minute per IP
        """
        queryset = Page.objects.filter(is_published=True)
        
        # Parent filtreleme
        parent_param = request.query_params.get('parent')
        if parent_param is not None:
            if parent_param.lower() == 'null':
                queryset = queryset.filter(parent__isnull=True)
            else:
                try:
                    parent_id = int(parent_param)
                    queryset = queryset.filter(parent_id=parent_id)
                except ValueError:
                    return Response(
                        {'detail': 'Geçersiz parent parametresi'},
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
        queryset = queryset.order_by('order', 'title')
        
        serializer = PageListSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """
        Yeni sayfa oluştur (Admin only)
        
        Rate limit: 30 requests per hour per user or IP
        """
        serializer = PageCreateUpdateSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                page = serializer.save()
                
                # Return created page data
                response_serializer = PageDetailSerializer(page)
                return Response(
                    response_serializer.data,
                    status=status.HTTP_201_CREATED
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Sayfa oluşturulurken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method=['PUT', 'PATCH', 'DELETE']), name='dispatch')
class PageDetailAPIView(APIView):
    """
    Sayfa detay, güncelleme ve silme endpoint (ID ile)
    GET: Sayfa detayını döndürür (AllowAny)
    PUT/PATCH: Sayfa güncelle (IsAdminUser)
    DELETE: Sayfa sil (IsAdminUser)
    """
    
    def get_permissions(self):
        """GET için AllowAny, PUT/PATCH/DELETE için IsAdminUser"""
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get_object(self, pk):
        """ID ile sayfa getir"""
        return get_object_or_404(Page, pk=pk, is_published=True)
    
    def get(self, request, pk):
        """
        ID'ye göre sayfa detayını getir
        
        Rate limit: 60 requests per minute per IP
        """
        page = self.get_object(pk)
        serializer = PageDetailSerializer(page)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """
        Sayfa güncelle - tüm alanlar (Admin only)
        
        Rate limit: 30 requests per hour per user or IP
        """
        page = get_object_or_404(Page, pk=pk)
        serializer = PageCreateUpdateSerializer(page, data=request.data)
        
        if serializer.is_valid():
            try:
                page = serializer.save()
                
                # Return updated page data
                response_serializer = PageDetailSerializer(page)
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Sayfa güncellenirken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, pk):
        """
        Sayfa kısmi güncelle - sadece gönderilen alanlar (Admin only)
        
        Rate limit: 30 requests per hour per user or IP
        """
        page = get_object_or_404(Page, pk=pk)
        serializer = PageCreateUpdateSerializer(page, data=request.data, partial=True)
        
        if serializer.is_valid():
            try:
                page = serializer.save()
                
                # Return updated page data
                response_serializer = PageDetailSerializer(page)
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )
                
            except Exception as e:
                return Response(
                    {'detail': 'Sayfa güncellenirken bir hata oluştu'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """
        Sayfa sil (Admin only)
        
        Rate limit: 30 requests per hour per user or IP
        """
        page = get_object_or_404(Page, pk=pk)
        
        try:
            page_title = page.title
            page.delete()
            
            return Response(
                {'detail': f'"{page_title}" sayfası başarıyla silindi'},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'detail': 'Sayfa silinirken bir hata oluştu'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
class PageSlugDetailAPIView(APIView):
    """
    Sayfa detay endpoint (Slug ile - SEO friendly)
    GET: Slug'a göre sayfa detayını döndürür
    Rate limited: 60 requests per minute per IP
    """
    permission_classes = [AllowAny]
    
    def get(self, request, slug):
        """
        Slug'a göre sayfa detayını getir
        """
        page = get_object_or_404(Page, slug=slug, is_published=True)
        serializer = PageDetailSerializer(page)
        return Response(serializer.data, status=status.HTTP_200_OK)


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='get')
class PageTreeAPIView(APIView):
    """
    Sayfa ağacı endpoint - hierarchical yapıyı döndürür
    GET: Tüm sayfaları ağaç yapısında listeler
    Rate limited: 60 requests per minute per IP
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Sayfaları hierarchical tree yapısında döndürür
        """
        def build_tree(parent=None):
            """Recursive tree builder"""
            pages = Page.objects.filter(
                parent=parent,
                is_published=True
            ).order_by('order', 'title')
            
            tree = []
            for page in pages:
                node = {
                    'id': page.id,
                    'title': page.title,
                    'slug': page.slug,
                    'url': page.get_absolute_url(),
                    'order': page.order,
                    'children': build_tree(parent=page)
                }
                tree.append(node)
            
            return tree
        
        tree = build_tree()
        return Response(tree, status=status.HTTP_200_OK)
