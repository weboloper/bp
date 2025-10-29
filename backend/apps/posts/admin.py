from django.contrib import admin
from .models import Post, Comment
from django_summernote.admin import SummernoteModelAdmin

@admin.register(Post)
class PostAdmin(SummernoteModelAdmin):
    list_display = ['title', 'author', 'is_published', 'created_at', 'updated_at']
    list_filter = ['is_published', 'created_at', 'author']
    search_fields = ['title', 'content', 'author__username', 'author__email']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    summernote_fields = ('content',)
    
    fieldsets = (
        ('Post Bilgileri', {
            'fields': ('title', 'content', 'author')
        }),
        ('Ayarlar', {
            'fields': ('is_published',)
        }),
        ('Tarihler', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ['post', 'author', 'content_preview', 'created_at']
    list_filter = ['created_at', 'author']
    search_fields = ['content', 'author__username', 'post__title']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    def content_preview(self, obj):
        """Show first 50 characters of content"""
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    
    content_preview.short_description = 'İçerik Önizleme'
