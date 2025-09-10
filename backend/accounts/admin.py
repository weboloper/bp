"""
Accounts admin configuration
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User, Profile


class ProfileInline(admin.StackedInline):
    """
    Inline Profile admin for User admin
    """
    model = Profile
    can_delete = False
    verbose_name_plural = _('Profil')
    extra = 0
    fields = (
        'profile_image',
        'bio',
        'website',
        'location',
        'is_public',
        'show_email',
        'show_phone',
        'email_notifications',
        'sms_notifications',
    )


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom User admin
    """
    inlines = (ProfileInline,)
    
    # List display
    list_display = (
        'email',
        'first_name',
        'last_name',
        'is_active',
        'is_staff',
        'is_verified',
        'date_joined',
    )
    
    # List filters
    list_filter = (
        'is_active',
        'is_staff',
        'is_superuser',
        'is_verified',
        'date_joined',
        'last_login',
    )
    
    # Search fields
    search_fields = (
        'email',
        'first_name',
        'last_name',
        'phone_number',
    )
    
    # Ordering
    ordering = ('-date_joined',)
    
    # Filter horizontal
    filter_horizontal = (
        'groups',
        'user_permissions',
    )
    
    # Fieldsets for detail view
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        (_('Kişisel Bilgiler'), {
            'fields': (
                'first_name',
                'last_name',
                'phone_number',
                'date_of_birth',
            )
        }),
        (_('İzinler'), {
            'fields': (
                'is_active',
                'is_staff',
                'is_superuser',
                'is_verified',
                'groups',
                'user_permissions',
            ),
        }),
        (_('Önemli Tarihler'), {
            'fields': ('last_login', 'date_joined')
        }),
    )
    
    # Add fieldsets
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email',
                'first_name',
                'last_name',
                'password1',
                'password2',
                'is_active',
                'is_staff',
            ),
        }),
    )
    
    # Readonly fields
    readonly_fields = ('date_joined', 'last_login')
    
    # Actions
    actions = ['activate_users', 'deactivate_users', 'verify_users']
    
    def activate_users(self, request, queryset):
        """Activate selected users"""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} kullanıcı aktif hale getirildi.')
    activate_users.short_description = _('Seçili kullanıcıları aktif hale getir')
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users"""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} kullanıcı pasif hale getirildi.')
    deactivate_users.short_description = _('Seçili kullanıcıları pasif hale getir')
    
    def verify_users(self, request, queryset):
        """Verify selected users"""
        updated = queryset.update(is_verified=True)
        self.message_user(request, f'{updated} kullanıcı doğrulandı.')
    verify_users.short_description = _('Seçili kullanıcıları doğrula')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    """
    Profile admin
    """
    # List display
    list_display = (
        'user',
        'location',
        'gender',
        'is_public',
        'email_notifications',
        'created_at',
    )
    
    # List filters
    list_filter = (
        'gender',
        'is_public',
        'email_notifications',
        'sms_notifications',
        'show_email',
        'show_phone',
        'created_at',
    )
    
    # Search fields
    search_fields = (
        'user__email',
        'user__first_name',
        'user__last_name',
        'location',
        'bio',
    )
    
    # Ordering
    ordering = ('-created_at',)
    
    # Fieldsets
    fieldsets = (
        (_('Temel Bilgiler'), {
            'fields': (
                'user',
                'profile_image',
                'bio',
                'website',
                'location',
                'gender',
            )
        }),
        (_('Gizlilik Ayarları'), {
            'fields': (
                'is_public',
                'show_email',
                'show_phone',
            )
        }),
        (_('Bildirim Tercihleri'), {
            'fields': (
                'email_notifications',
                'sms_notifications',
            )
        }),
        (_('Tarihler'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    # Readonly fields
    readonly_fields = ('created_at', 'updated_at')
    
    # Raw ID fields (for performance with large datasets)
    raw_id_fields = ('user',)
