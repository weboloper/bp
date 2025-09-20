from django.contrib import admin
from .models import Page


@admin.register(Page)
class PageAdmin(admin.ModelAdmin):
    list_display = ['title', 'slug', 'parent', 'is_published', 'order', 'created_at']
    list_filter = ['is_published', 'parent', 'created_at']
    search_fields = ['title', 'content']
    prepopulated_fields = {'slug': ('title',)}
    list_editable = ['is_published', 'order']
    ordering = ['order', 'title']
    
    fieldsets = (
        (None, {
            'fields': ('title', 'slug', 'parent')
        }),
        ('İçerik', {
            'fields': ('content',)
        }),
        ('Ayarlar', {
            'fields': ('is_published', 'order'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('parent')
