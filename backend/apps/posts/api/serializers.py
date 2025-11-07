from rest_framework import serializers
from posts.models import Post
from django.contrib.auth import get_user_model

User = get_user_model()


# ============================================================================
# Author Serializer - Nested kullanımlar için
# ============================================================================

class AuthorSerializer(serializers.ModelSerializer):
    """
    Author bilgilerini minimal olarak döndürür.
    Post'larda nested olarak kullanılır.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        read_only_fields = ['id', 'username', 'email']


# ============================================================================
# 1. BasicSerializer - Nested kullanımlar için
# ============================================================================

class PostBasicSerializer(serializers.ModelSerializer):
    """
    Basic serializer for Post (used in nested representations).
    Minimal veri içerir - circular reference'ları önler.
    """
    author_username = serializers.CharField(source='author.username', read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'title', 'author_username', 'is_published', 'created_at']
        read_only_fields = ['id', 'author_username', 'created_at']


# ============================================================================
# 2. Serializer - CRUD operasyonları için
# ============================================================================

class PostSerializer(serializers.ModelSerializer):
    """
    Serializer for Post model.
    Liste, oluşturma ve güncelleme operasyonları için kullanılır.
    """
    # Read-only computed fields
    author = AuthorSerializer(read_only=True)
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = [
            'id',
            'title',
            'content',
            'author',
            'is_published',
            'is_owner',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']

    def get_is_owner(self, obj):
        """Mevcut kullanıcının post sahibi olup olmadığını kontrol eder"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.author == request.user
        return False

    # ========================================================================
    # Validation
    # ========================================================================

    def validate_title(self, value):
        """Başlık validasyonu"""
        title = value.strip() if value else ''

        if not title:
            raise serializers.ValidationError('Başlık boş olamaz')
        if len(title) < 3:
            raise serializers.ValidationError('Başlık en az 3 karakter olmalıdır')
        if len(title) > 255:
            raise serializers.ValidationError('Başlık en fazla 255 karakter olabilir')

        return title

    def validate_content(self, value):
        """İçerik validasyonu"""
        content = value.strip() if value else ''

        if not content:
            raise serializers.ValidationError('İçerik boş olamaz')
        if len(content) < 10:
            raise serializers.ValidationError('İçerik en az 10 karakter olmalıdır')

        return content


# ============================================================================
# 3. DetailSerializer - Tek kayıt detayı için
# ============================================================================

class PostDetailSerializer(PostSerializer):
    """
    Detailed serializer for Post with nested relationships.
    Tek bir post'un detaylı görünümünde kullanılır.

    Şu an için ek nested data yok, ama ileride comments gibi
    ilişkili veriler eklenebilir.
    """
    # İleride comments eklenirse:
    # comments_count = serializers.SerializerMethodField()

    class Meta(PostSerializer.Meta):
        fields = PostSerializer.Meta.fields  # + ['comments_count']

    # def get_comments_count(self, obj):
    #     """Yorum sayısını döndürür"""
    #     return obj.comments.count()
