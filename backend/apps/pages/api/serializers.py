from rest_framework import serializers
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
            raise serializers.ValidationError('Slug gerekli')

        # Update işleminde mevcut kaydın slug'ını kontrol etme
        if self.instance:
            if Page.objects.exclude(pk=self.instance.pk).filter(slug=slug).exists():
                raise serializers.ValidationError('Bu slug zaten kullanılıyor')
        else:
            if Page.objects.filter(slug=slug).exists():
                raise serializers.ValidationError('Bu slug zaten kullanılıyor')

        return slug

    def validate_title(self, value):
        """Başlık validasyonu"""
        title = value.strip()

        if not title:
            raise serializers.ValidationError('Başlık gerekli')
        if len(title) < 3:
            raise serializers.ValidationError('Başlık en az 3 karakter olmalı')
        if len(title) > 200:
            raise serializers.ValidationError('Başlık en fazla 200 karakter olabilir')

        return title

    def validate_content(self, value):
        """İçerik validasyonu"""
        content = value.strip()

        if not content:
            raise serializers.ValidationError('İçerik gerekli')
        if len(content) < 10:
            raise serializers.ValidationError('İçerik en az 10 karakter olmalı')

        return content

    def validate_parent(self, value):
        """Parent validasyonu - circular reference kontrolü"""
        if value:
            # Kendisi parent olamaz
            if self.instance and value.id == self.instance.id:
                raise serializers.ValidationError('Sayfa kendisinin alt sayfası olamaz')

            # Circular reference kontrolü
            if self.instance:
                current = value
                while current:
                    if current.id == self.instance.id:
                        raise serializers.ValidationError('Circular reference oluşturulması engellenmiştir')
                    current = current.parent

        return value

    def validate_order(self, value):
        """Sıralama validasyonu"""
        if value < 0:
            raise serializers.ValidationError('Sıralama değeri negatif olamaz')
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
