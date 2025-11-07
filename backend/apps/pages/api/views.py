from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAdminUser
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

from pages.models import Page
from .serializers import (
    PageBasicSerializer,
    PageSerializer,
    PageDetailSerializer
)


@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='list')
@method_decorator(ratelimit(key='ip', rate='60/m', method='GET'), name='retrieve')
@method_decorator(ratelimit(key='user_or_ip', rate='30/h', method=['POST', 'PUT', 'PATCH', 'DELETE']), name='dispatch')
class PageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Page model.
    Provides CRUD operations for pages.

    List/Retrieve: AllowAny (published pages only)
    Create/Update/Delete: IsAdminUser only

    Endpoints:
    - GET    /api/pages/              - Liste (published only)
    - POST   /api/pages/              - Yeni sayfa oluştur (admin only)
    - GET    /api/pages/{slug}/       - Detay (published only)
    - PUT    /api/pages/{slug}/       - Güncelle (admin only)
    - PATCH  /api/pages/{slug}/       - Kısmi güncelle (admin only)
    - DELETE /api/pages/{slug}/       - Sil (admin only)
    - GET    /api/pages/tree/         - Hierarchical tree yapısı
    """
    queryset = Page.objects.all()
    lookup_field = 'slug'

    def get_permissions(self):
        """
        List ve Retrieve için AllowAny, diğer işlemler için IsAdminUser.
        """
        if self.action in ['list', 'retrieve', 'tree']:
            return [AllowAny()]
        return [IsAdminUser()]

    def get_serializer_class(self):
        """Action'a göre uygun serializer döndür"""
        if self.action == 'retrieve':
            return PageDetailSerializer
        return PageSerializer

    def get_queryset(self):
        """
        Filter queryset and optimize queries.

        Query Parameters:
        - parent: Parent ID'ye göre filtrele (ör: ?parent=1 veya ?parent=null)
        - search: Başlık veya içeriğe göre ara (ör: ?search=hakkımızda)
        """
        user = self.request.user

        # Admin için tüm sayfaları göster
        if user.is_staff or user.is_superuser:
            queryset = Page.objects.all()
        else:
            # Normal kullanıcılar için sadece yayınlanmış sayfalar
            queryset = Page.objects.filter(is_published=True)

        # Query optimization
        queryset = queryset.select_related('parent')
        queryset = queryset.prefetch_related('children')

        # Parent filtreleme
        parent_param = self.request.query_params.get('parent')
        if parent_param is not None:
            if parent_param.lower() == 'null':
                queryset = queryset.filter(parent__isnull=True)
            else:
                try:
                    parent_id = int(parent_param)
                    queryset = queryset.filter(parent_id=parent_id)
                except ValueError:
                    pass  # Invalid parent_id, ignore

        # Arama
        search_query = self.request.query_params.get('search')
        if search_query:
            queryset = queryset.filter(title__icontains=search_query) | queryset.filter(content__icontains=search_query)

        return queryset.order_by('order', 'title')

    def create(self, request, *args, **kwargs):
        """
        Yeni sayfa oluştur (Admin only).

        POST /api/pages/
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            try:
                page = serializer.save()

                # Return created page data with detail serializer
                response_serializer = PageDetailSerializer(page)
                return Response(
                    response_serializer.data,
                    status=status.HTTP_201_CREATED
                )

            except Exception as e:
                return Response(
                    {'detail': f'Sayfa oluşturulurken bir hata oluştu: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        """
        Sayfa güncelle - tüm alanlar (Admin only).

        PUT /api/pages/{slug}/
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        if serializer.is_valid():
            try:
                page = serializer.save()

                # Return updated page data with detail serializer
                response_serializer = PageDetailSerializer(page)
                return Response(
                    response_serializer.data,
                    status=status.HTTP_200_OK
                )

            except Exception as e:
                return Response(
                    {'detail': f'Sayfa güncellenirken bir hata oluştu: {str(e)}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        """
        Sayfa kısmi güncelle - sadece gönderilen alanlar (Admin only).

        PATCH /api/pages/{slug}/
        """
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Sayfa sil (Admin only).

        DELETE /api/pages/{slug}/
        """
        instance = self.get_object()

        try:
            page_title = instance.title
            instance.delete()

            return Response(
                {'detail': f'"{page_title}" sayfası başarıyla silindi'},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {'detail': f'Sayfa silinirken bir hata oluştu: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # ========================================================================
    # Custom Actions
    # ========================================================================

    @action(detail=False, methods=['get'], url_path='tree')
    def tree(self, request):
        """
        Sayfaları hierarchical tree yapısında döndürür.

        GET /api/pages/tree/

        Returns:
            200: Tree yapısında sayfa listesi
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

        tree_data = build_tree()
        return Response(tree_data, status=status.HTTP_200_OK)
