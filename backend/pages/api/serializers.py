from rest_framework import serializers
from pages.models import Page


class PageListSerializer(serializers.ModelSerializer):
    """
    List sayfalar için serializer (liste görünümü)
    """
    children_count = serializers.SerializerMethodField()
    parent_title = serializers.CharField(source='parent.title', read_only=True, allow_null=True)
    url = serializers.SerializerMethodField()
    
    class Meta:
        model = Page
        fields = [
            'id',
            'title',
            'slug',
            'parent',
            'parent_title',
            'is_published',
            'order',
            'created_at',
            'updated_at',
            'children_count',
            'url'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_children_count(self, obj):
        """Alt sayfa sayısını döndürür"""
        return obj.children.filter(is_published=True).count()
    
    def get_url(self, obj):
        """Sayfa URL'ini döndürür"""
        return obj.get_absolute_url()


class PageDetailSerializer(serializers.ModelSerializer):
    """
    Detaylı sayfa serializer (detay görünümü)
    """
    children = serializers.SerializerMethodField()
    breadcrumbs = serializers.SerializerMethodField()
    parent_title = serializers.CharField(source='parent.title', read_only=True, allow_null=True)
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
            'created_at',
            'updated_at',
            'children',
            'breadcrumbs',
            'url'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_children(self, obj):
        """Alt sayfaları döndürür"""
        children = obj.get_children()
        return [{
            'id': child.id,
            'title': child.title,
            'slug': child.slug,
            'url': child.get_absolute_url(),
            'order': child.order
        } for child in children]
    
    def get_breadcrumbs(self, obj):
        """Breadcrumb yolunu döndürür"""
        breadcrumbs = obj.get_breadcrumbs()
        return [{
            'id': page.id,
            'title': page.title,
            'slug': page.slug,
            'url': page.get_absolute_url()
        } for page in breadcrumbs]
    
    def get_url(self, obj):
        """Sayfa URL'ini döndürür"""
        return obj.get_absolute_url()


class PageCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Sayfa oluşturma ve güncelleme için serializer
    """
    class Meta:
        model = Page
        fields = [
            'title',
            'slug',
            'content',
            'parent',
            'is_published',
            'order'
        ]
    
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
            if self.instance and value.id == self.instance.id:
                raise serializers.ValidationError('Sayfa kendisinin alt sayfası olamaz')
            
            # Parent'ın children'larını kontrol et
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
