from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, Profile


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = _('Profil')
    extra = 0
    fields = ('first_name', 'last_name', 'birth_date', 'bio', 'avatar')


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    
    list_display = (
        'username',
        'email',
        'is_active',
        'is_staff',
        'is_verified',
        'date_joined',
    )
    
    list_filter = (
        'is_active',
        'is_staff', 
        'is_superuser',
        'is_verified',
        'date_joined',
        'last_login',
    )
    
    search_fields = ('username', 'email', 'profile__first_name', 'profile__last_name')
    ordering = ('-date_joined',)
    filter_horizontal = ('groups', 'user_permissions')
    
    fieldsets = (
        (None, {
            'fields': ('username', 'email', 'password')
        }),
        (_('İzinler'), {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'is_verified',
                'groups',
                'user_permissions',
            )
        }),
        (_('Önemli Tarihler'), {
            'fields': ('last_login', 'date_joined')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username',
                'email',
                'password1',
                'password2',
                'is_active',
                'is_staff',
            ),
        }),
    )
    
    readonly_fields = ('date_joined', 'last_login')
    
    actions = ['activate_users', 'deactivate_users', 'verify_users']
    
    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} kullanıcı aktif hale getirildi.')
    activate_users.short_description = _('Seçili kullanıcıları aktif hale getir')
    
    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)  
        self.message_user(request, f'{updated} kullanıcı pasif hale getirildi.')
    deactivate_users.short_description = _('Seçili kullanıcıları pasif hale getir')
    
    def verify_users(self, request, queryset):
        updated = queryset.update(is_verified=True)
        self.message_user(request, f'{updated} kullanıcı doğrulandı.')
    verify_users.short_description = _('Seçili kullanıcıları doğrula')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name', 'birth_date', 'created_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'first_name', 'last_name', 'bio')
    ordering = ('-created_at',)
    
    fieldsets = (
        (_('Temel Bilgiler'), {
            'fields': ('user', 'first_name', 'last_name', 'birth_date', 'bio', 'avatar')
        }),
        (_('Tarihler'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)
