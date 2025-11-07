# API Development Standards

Bu doküman, BP Salon projesinde API geli_tirme standartlar1n1 tan1mlar. Tüm yeni API modülleri bu standartlar1 takip etmelidir.

## 0çindekiler

- [Dizin Yap1s1](#dizin-yap1s1)
- [Serializer Pattern](#serializer-pattern)
- [ViewSet Pattern](#viewset-pattern)
- [URL Configuration](#url-configuration)
- [Admin Interface](#admin-interface)
- [Best Practices](#best-practices)

---

41021_020000.sql.gz

## Dizin Yap1s1

Her Django app içinde `api` klasörü olu_turulmal1d1r:

```
app_name/
├── models.py
├── admin.py
├── api/
│   ├── __init__.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
├── migrations/
├── ...
```

---

## Serializer Pattern

### 3-Katmanl1 Serializer Yap1s1

Her model için **3 farkl1 serializer** olu_turulmal1d1r:

#### 1. **BasicSerializer** - Nested Kullan1mlar 0çin

```python
class ModelNameBasicSerializer(serializers.ModelSerializer):
    """Basic serializer for ModelName (used in nested representations)."""

    class Meta:
        model = ModelName
        fields = ['id', 'name', 'slug', 'created_at', 'updated_at']
        read_only_fields = ['slug', 'created_at', 'updated_at']
```

**Kullan1m Amac1:**

- 0ç içe (nested) reprezentasyonlarda kullan1l1r
- Circular reference'lar1 önler
- Minimal veri içerir (sadece temel bilgiler)

**Ne zaman kullan1l1r:**

- Ba_ka bir modelin detail view'1nda nested olarak gösterilecekse
- 0li_kili verileri gösterirken sonsuz döngüyü engellemek için

#### 2. **Serializer** - CRUD Operasyonlar1 0çin

```python
class ModelNameSerializer(serializers.ModelSerializer):
    """Serializer for ModelName model."""

    # Read-only computed fields
    related_name = serializers.CharField(source='related.name', read_only=True)
    items_count = serializers.SerializerMethodField()

    class Meta:
        model = ModelName
        fields = [
            'id', 'name', 'slug', 'description',
            'related', 'related_name', 'items_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['slug', 'created_at', 'updated_at']

    def get_items_count(self, obj):
        """Get count of related items."""
        return obj.items.count()

    def validate_field_name(self, value):
        """Validate specific field."""
        if not value:
            raise serializers.ValidationError("Field cannot be empty.")
        return value

    def validate(self, attrs):
        """Cross-field validation."""
        # Custom validation logic
        return attrs
```

**Kullan1m Amac1:**

- List, Create, Update, Delete operasyonlar1nda kullan1l1r
- Tüm fieldlar1 içerir
- Computed fields (count, vs.) içerebilir
- Nested data içermez (performans için)

**Ne zaman kullan1l1r:**

- `GET /api/model-names/` - Liste görünümü
- `POST /api/model-names/` - Yeni kay1t olu_turma
- `PUT/PATCH /api/model-names/{id}/` - Güncelleme

#### 3. **DetailSerializer** - Tek Kay1t Detay1 0çin

```python
class ModelNameDetailSerializer(ModelNameSerializer):
    """Detailed serializer for ModelName with nested relationships."""

    related_items = serializers.SerializerMethodField()

    class Meta(ModelNameSerializer.Meta):
        fields = ModelNameSerializer.Meta.fields + ['related_items']

    def get_related_items(self, obj):
        """Get related items with basic serializer."""
        from .serializers import RelatedItemBasicSerializer
        return RelatedItemBasicSerializer(
            obj.related_items.filter(is_active=True),
            many=True
        ).data
```

**Kullan1m Amac1:**

- Tek bir kayd1n detayl1 görünümünde kullan1l1r
- Nested relationships içerir
- 0li_kili verileri gösterir (BasicSerializer kullanarak)

**Ne zaman kullan1l1r:**

- `GET /api/model-names/{id}/` - Detay görünümü

---

### Serializer Örnekleri

#### Örnek 1: Location Model

```python
# 1. BasicSerializer - Nested kullan1m için
class LocationBasicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['id', 'name', 'slug', 'address']
        read_only_fields = ['slug']

# 2. Serializer - CRUD için
class LocationSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.name', read_only=True)
    staff_count = serializers.SerializerMethodField()

    class Meta:
        model = Location
        fields = [
            'id', 'name', 'slug', 'company', 'company_name',
            'address', 'working_hours', 'staff_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['slug', 'created_at', 'updated_at']

    def get_staff_count(self, obj):
        return obj.staff_members.filter(is_active=True).count()

# 3. DetailSerializer - Detay görünümü için
class LocationDetailSerializer(LocationSerializer):
    staff_members = serializers.SerializerMethodField()

    class Meta(LocationSerializer.Meta):
        fields = LocationSerializer.Meta.fields + ['staff_members']

    def get_staff_members(self, obj):
        from .serializers import StaffBasicSerializer
        return StaffBasicSerializer(
            obj.staff_members.filter(is_active=True),
            many=True
        ).data
```

---

## ViewSet Pattern

### ModelViewSet Kullan1m1

```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class ModelNameViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ModelName model.
    Provides CRUD operations for model-names.
    """
    queryset = ModelName.objects.all()
    permission_classes = [IsAuthenticated]
    lookup_field = 'slug'  # veya 'pk'

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'retrieve':
            return ModelNameDetailSerializer
        return ModelNameSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions and optimize queries."""
        user = self.request.user

        # Admin kontrolü
        if user.is_staff or user.is_superuser:
            queryset = ModelName.objects.all()
        else:
            # Multi-tenant filtering
            queryset = ModelName.objects.filter(company__owner=user)

        # Query optimization
        queryset = queryset.select_related('company', 'related_model')
        queryset = queryset.prefetch_related('items')

        # Optional filters from query params
        filter_param = self.request.query_params.get('filter_param', None)
        if filter_param:
            queryset = queryset.filter(field=filter_param)

        return queryset

    def perform_create(self, serializer):
        """Set additional fields on create."""
        serializer.save(created_by=self.request.user)

    # Custom actions
    @action(detail=True, methods=['post'])
    def custom_action(self, request, slug=None):
        """
        Custom action description.

        POST /api/model-names/{slug}/custom_action/
        Body: {"param": "value"}
        """
        obj = self.get_object()
        # Custom logic
        return Response({'message': 'Success'})

    @action(detail=True, methods=['get'])
    def related_items(self, request, slug=None):
        """
        Get related items for this object.

        GET /api/model-names/{slug}/related_items/
        """
        obj = self.get_object()
        items = obj.related_items.all()
        serializer = RelatedItemSerializer(items, many=True)
        return Response(serializer.data)
```

### ViewSet Standartlar1

1. **Docstring**: Her ViewSet ve action için aç1klay1c1 docstring
2. **Permission Classes**: Her zaman permission_classes tan1mla
3. **get_queryset**: Multi-tenant filtering ve query optimization
4. **get_serializer_class**: Action'a göre uygun serializer döndür
5. **Custom Actions**: @action decorator ile özel endpoint'ler

---

## URL Configuration

### Router Kullan1m1

```python
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ModelNameViewSet,
    AnotherModelViewSet,
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'model-names', ModelNameViewSet, basename='modelname')
router.register(r'another-models', AnotherModelViewSet, basename='anothermodel')

# URL patterns
urlpatterns = [
    path('', include(router.urls)),
]
```

### URL Naming Conventions

- **Çoul kullan**: `companies`, `locations`, `staff` (tekil deil)
- **Kebab-case**: `company-types`, `purchase-orders`
- **Basename**: Model ad1n1n lowercase hali (tek kelime)

---

## Admin Interface

### Admin S1n1f1 Standartlar1

```python
from django.contrib import admin
from .models import ModelName

@admin.register(ModelName)
class ModelNameAdmin(admin.ModelAdmin):
    """Admin interface for ModelName model."""

    # List view configuration
    list_display = ['name', 'slug', 'company', 'is_active', 'created_at']
    list_filter = ['is_active', 'company', 'created_at']
    search_fields = ['name', 'slug', 'company__name', 'description']
    readonly_fields = ['slug', 'created_at', 'updated_at']

    # Autocomplete for foreign keys
    autocomplete_fields = ['company', 'related_model']

    # Date hierarchy
    date_hierarchy = 'created_at'

    # Ordering
    ordering = ['-created_at']

    # Fieldsets for detail view
    fieldsets = (
        ('Temel Bilgiler', {
            'fields': ('name', 'slug', 'company', 'description')
        }),
        ('Ayarlar', {
            'fields': ('is_active', 'settings')
        }),
        ('Zaman Bilgileri', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        """Optimize queryset with select_related/prefetch_related."""
        return super().get_queryset(request).select_related(
            'company', 'related_model'
        ).prefetch_related('items')
```

### Admin Standartlar1

1. **@admin.register**: Decorator kullan (admin.site.register yerine)
2. **Docstring**: Her admin s1n1f1 için aç1klama
3. **list_display**: En önemli 5-7 alan
4. **list_filter**: Filtreleme için gerekli alanlar
5. **search_fields**: Arama yap1labilecek alanlar
6. **autocomplete_fields**: ForeignKey'ler için autocomplete
7. **readonly_fields**: Otomatik olu_turulan alanlar
8. **fieldsets**: Organize edilmi\_ form gruplar1
9. **get_queryset**: Query optimization (select_related, prefetch_related)

---

## Best Practices

### 1. Multi-Tenant Data Isolation

**Her ViewSet'te company-based filtering:**

```python
def get_queryset(self):
    user = self.request.user
    if user.is_staff or user.is_superuser:
        return ModelName.objects.all()
    return ModelName.objects.filter(company__owner=user)
```

### 2. Query Optimization

**N+1 query problemini önle:**

```python
#  Good
queryset = queryset.select_related('company', 'user')
queryset = queryset.prefetch_related('items', 'tags')

# L Bad
queryset = ModelName.objects.all()  # Her item için extra query
```

### 3. Validation

**Serializer seviyesinde validation:**

```python
def validate_field(self, value):
    """Field-level validation."""
    if not value:
        raise serializers.ValidationError("Field required.")
    return value

def validate(self, attrs):
    """Object-level validation."""
    if attrs['start_date'] > attrs['end_date']:
        raise serializers.ValidationError("Invalid date range.")
    return attrs
```

### 4. Error Handling

**Aç1klay1c1 error mesajlar1:**

```python
if not obj.is_active:
    return Response(
        {'error': 'This object is not active.'},
        status=status.HTTP_400_BAD_REQUEST
    )
```

### 5. Documentation

**Her endpoint için docstring:**

```python
@action(detail=True, methods=['post'])
def activate(self, request, pk=None):
    """
    Activate an object.

    POST /api/model-names/{id}/activate/

    Returns:
        200: Object activated successfully
        400: Object is already active
        404: Object not found
    """
```

### 6. Consistent Response Format

**Standart response format1:**

```python
# Success
return Response({
    'message': 'Operation successful',
    'data': serializer.data
})

# Error
return Response({
    'error': 'Error message',
    'details': error_details
}, status=status.HTTP_400_BAD_REQUEST)
```

---

## Checklist: Yeni API Modülü

Yeni bir API modülü olu_tururken kontrol listesi:

- [ ] `api/` klasörü olu_turuldu
- [ ] `__init__.py`, `serializers.py`, `views.py`, `urls.py` dosyalar1 olu_turuldu
- [ ] Her model için 3 serializer yaz1ld1 (Basic, Normal, Detail)
- [ ] ViewSet olu_turuldu ve `get_queryset()` override edildi
- [ ] Multi-tenant filtering eklendi
- [ ] Query optimization yap1ld1 (select_related, prefetch_related)
- [ ] Permission classes tan1mland1
- [ ] Custom actions için docstring yaz1ld1
- [ ] Admin interface olu_turuldu
- [ ] Admin'de fieldsets kullan1ld1
- [ ] Admin'de query optimization yap1ld1
- [ ] URL configuration tamamland1 (router ile)
- [ ] Tüm endpoint'ler test edildi

---
