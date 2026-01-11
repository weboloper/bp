from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from .models import Page
from django_summernote.admin import SummernoteModelAdmin


@admin.register(Page)
class PageAdmin(SummernoteModelAdmin):
    list_display = ['title', 'slug', 'parent', 'is_published', 'order', 'created_at']
    list_filter = ['is_published', 'parent', 'created_at']
    search_fields = ['title', 'content']
    prepopulated_fields = {'slug': ('title',)}
    list_editable = ['is_published', 'order']
    ordering = ['order', 'title']
    summernote_fields = ('content',)
    
    fieldsets = (
        (None, {
            'fields': ('title', 'slug', 'parent')
        }),
        (_('Content'), {
            'fields': ('content',)
        }),
        (_('Settings'), {
            'fields': ('is_published', 'order'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('parent')
