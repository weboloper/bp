from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from pages.models import Page


# ============================================================================
# 1. BasicSerializer - Nested kullanımlar için
# ============================================================================

class PageBasicSerializer(serializers.ModelSerializer):
    """
    Basic serializer for Page (used in nested representations).
    Minimal veri içerir - circular reference'ları önler.
    """
    url = serializers.SerializerMethodField()

    class Meta:
        model = Page
        fields = ['id', 'title', 'slug', 'url', 'order']
        read_only_fields = ['id', 'slug']

    def get_url(self, obj):
        """Sayfa URL'ini döndürür"""
        return obj.get_absolute_url()


# ============================================================================
# 2. Serializer - CRUD operasyonları için
# ============================================================================

class PageSerializer(serializers.ModelSerializer):
    """
    Serializer for Page model.
    Liste, oluşturma ve güncelleme operasyonları için kullanılır.
    """
    # Read-only computed fields
    parent_title = serializers.CharField(source='parent.title', read_only=True, allow_null=True)
    children_count = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()

    class Meta:
        model = Page
        fields = [
            'id',
            'title',
            'slug',
            'content',
            'parent',
            'parent_title',
            'is_published',
            'order',
            'children_count',
            'url',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_children_count(self, obj):
        """Alt sayfa sayısını döndürür"""
        return obj.children.filter(is_published=True).count()

    def get_url(self, obj):
        """Sayfa URL'ini döndürür"""
        return obj.get_absolute_url()

    # ========================================================================
    # Validation
    # ========================================================================

    def validate_slug(self, value):
        """Slug validasyonu"""
        slug = value.strip()

        if not slug:
            raise serializers.ValidationError(_('Slug is required'))

        # Update işleminde mevcut kaydın slug'ını kontrol etme
        if self.instance:
            if Page.objects.exclude(pk=self.instance.pk).filter(slug=slug).exists():
                raise serializers.ValidationError(_('This slug is already in use'))
        else:
            if Page.objects.filter(slug=slug).exists():
                raise serializers.ValidationError(_('This slug is already in use'))

        return slug

    def validate_title(self, value):
        """Başlık validasyonu"""
        title = value.strip()

        if not title:
            raise serializers.ValidationError(_('Title is required'))
        if len(title) < 3:
            raise serializers.ValidationError(_('Title must be at least 3 characters'))
        if len(title) > 200:
            raise serializers.ValidationError(_('Title must be at most 200 characters'))

        return title

    def validate_content(self, value):
        """İçerik validasyonu"""
        content = value.strip()

        if not content:
            raise serializers.ValidationError(_('Content is required'))
        if len(content) < 10:
            raise serializers.ValidationError(_('Content must be at least 10 characters'))

        return content

    def validate_parent(self, value):
        """Parent validasyonu - circular reference kontrolü"""
        if value:
            # Kendisi parent olamaz
            if self.instance and value.id == self.instance.id:
                raise serializers.ValidationError(_('A page cannot be its own child page'))

            # Circular reference kontrolü
            if self.instance:
                current = value
                while current:
                    if current.id == self.instance.id:
                        raise serializers.ValidationError(_('Creating a circular reference is not allowed'))
                    current = current.parent

        return value

    def validate_order(self, value):
        """Sıralama validasyonu"""
        if value < 0:
            raise serializers.ValidationError(_('Order value cannot be negative'))
        return value


# ============================================================================
# 3. DetailSerializer - Tek kayıt detayı için
# ============================================================================

class PageDetailSerializer(PageSerializer):
    """
    Detailed serializer for Page with nested relationships.
    Tek bir sayfanın detaylı görünümünde kullanılır - nested data içerir.
    """
    children = serializers.SerializerMethodField()
    breadcrumbs = serializers.SerializerMethodField()

    class Meta(PageSerializer.Meta):
        fields = PageSerializer.Meta.fields + ['children', 'breadcrumbs']

    def get_children(self, obj):
        """Alt sayfaları BasicSerializer ile döndürür"""
        children = obj.get_children()
        return PageBasicSerializer(children, many=True).data

    def get_breadcrumbs(self, obj):
        """Breadcrumb yolunu BasicSerializer ile döndürür"""
        breadcrumbs = obj.get_breadcrumbs()
        return PageBasicSerializer(breadcrumbs, many=True).data
