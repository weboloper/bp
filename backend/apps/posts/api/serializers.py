from rest_framework import serializers
from posts.models import Post
from django.contrib.auth import get_user_model

User = get_user_model()


class AuthorSerializer(serializers.ModelSerializer):
    """Author bilgilerini minimal olarak döndür"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        read_only_fields = ['id', 'username', 'email']


class PostListSerializer(serializers.ModelSerializer):
    """
    Post listesi için serializer
    List endpoint'lerinde kullanılır
    """
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
            'created_at',
            'updated_at',
            'is_owner',
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']
    
    def get_is_owner(self, obj):
        """Check if current user is the owner"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.author == request.user
        return False


class PostDetailSerializer(serializers.ModelSerializer):
    """
    Post detayı için serializer
    Detail endpoint'lerinde kullanılır
    """
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
            'created_at',
            'updated_at',
            'is_owner',
        ]
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']
    
    def get_is_owner(self, obj):
        """Check if current user is the owner"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.author == request.user
        return False


class PostCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Post oluşturma ve güncelleme için serializer
    Create ve Update endpoint'lerinde kullanılır
    """
    
    class Meta:
        model = Post
        fields = [
            'title',
            'content',
            'is_published',
        ]
    
    def validate_title(self, value):
        """Başlık validasyonu"""
        if not value or not value.strip():
            raise serializers.ValidationError('Başlık boş olamaz')
        
        if len(value) < 3:
            raise serializers.ValidationError('Başlık en az 3 karakter olmalıdır')
        
        if len(value) > 255:
            raise serializers.ValidationError('Başlık en fazla 255 karakter olabilir')
        
        return value.strip()
    
    def validate_content(self, value):
        """İçerik validasyonu"""
        if not value or not value.strip():
            raise serializers.ValidationError('İçerik boş olamaz')
        
        if len(value) < 10:
            raise serializers.ValidationError('İçerik en az 10 karakter olmalıdır')
        
        return value.strip()
