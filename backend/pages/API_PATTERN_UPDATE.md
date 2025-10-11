# ✅ Pages API - RESTful Standart Pattern

## 🎯 Güncelleme Özeti

### Değişiklikler

**Önceki Yapı (Yanlış):**
```
❌ POST   /api/pages/admin/create/
❌ PUT    /api/pages/admin/<slug>/update/
❌ DELETE /api/pages/admin/<slug>/delete/
```
- Admin kontrolü URL'de yapılıyordu
- Slug ile güncelleme/silme yapılıyordu
- RESTful standartlara uymuyordu

**Yeni Yapı (Doğru):**
```
✅ GET    /api/pages/              # Liste (Public)
✅ POST   /api/pages/              # Oluştur (Admin)
✅ GET    /api/pages/<id>/         # ID ile detay (Public)
✅ PUT    /api/pages/<id>/         # ID ile güncelle (Admin)
✅ PATCH  /api/pages/<id>/         # ID ile kısmi güncelle (Admin)
✅ DELETE /api/pages/<id>/         # ID ile sil (Admin)
✅ GET    /api/pages/slug/<slug>/  # Slug ile detay (Public)
✅ GET    /api/pages/tree/         # Tree yapısı (Public)
```
- Admin kontrolü view'da `permission_classes` ile yapılıyor
- ID ile güncelleme/silme yapılıyor (güvenli)
- Slug sadece okuma için (SEO-friendly)
- RESTful standartlara uygun

---

## 🏗️ Yapı

### View'lar

1. **PageListCreateAPIView**
   - GET: Liste (AllowAny)
   - POST: Oluştur (IsAdminUser)
   - `get_permissions()` ile dinamik permission

2. **PageDetailAPIView** (ID ile)
   - GET: Detay (AllowAny)
   - PUT: Tam güncelleme (IsAdminUser)
   - PATCH: Kısmi güncelleme (IsAdminUser)
   - DELETE: Silme (IsAdminUser)
   - `get_permissions()` ile dinamik permission

3. **PageSlugDetailAPIView** (Slug ile)
   - GET: Detay (AllowAny)
   - Sadece okuma için

4. **PageTreeAPIView**
   - GET: Tree yapısı (AllowAny)

### URLs

```python
urlpatterns = [
    path('', PageListCreateAPIView.as_view(), name='page_list_create'),
    path('tree/', PageTreeAPIView.as_view(), name='page_tree'),
    path('slug/<slug:slug>/', PageSlugDetailAPIView.as_view(), name='page_slug_detail'),
    path('<int:pk>/', PageDetailAPIView.as_view(), name='page_detail'),
]
```

---

## 💡 Neden Bu Yapı?

### 1. RESTful Standartlar
- HTTP metodları doğru kullanılıyor
- Resource-based URL yapısı
- Endpoint'ler tahmin edilebilir

### 2. Güvenlik
- ID ile işlemler (değişmez, güvenli)
- Permission kontrolü view seviyesinde
- Rate limiting

### 3. Esneklik
- Hem ID hem slug desteği
- Dynamic permissions
- Public/Admin ayrımı net

### 4. Tutarlılık
- Tüm app'lerde aynı pattern kullanılabilir
- Accounts API ile aynı yapı
- Predictable behavior

---

## 🚀 Kullanım Örnekleri

### Frontend'de ID Kullanımı (Admin Panel)
```javascript
// Güncelleme
axios.patch(`/api/pages/${pageId}/`, {
  title: 'Yeni Başlık'
}, {
  headers: { Authorization: `Bearer ${token}` }
});

// Silme
axios.delete(`/api/pages/${pageId}/`, {
  headers: { Authorization: `Bearer ${token}` }
});
```

### Frontend'de Slug Kullanımı (Public)
```javascript
// SEO-friendly URL ile sayfa gösterimi
const { slug } = useParams(); // /hakkimizda
axios.get(`/api/pages/slug/${slug}/`);
```

---

## 📊 ID vs Slug

| Özellik | ID | Slug |
|---------|----|----|
| **Kullanım** | CRUD işlemleri | Okuma işlemleri |
| **Güvenlik** | Yüksek (değişmez) | Orta (değişebilir) |
| **SEO** | Düşük | Yüksek |
| **Hız** | Çok hızlı (primary key) | Hızlı (index) |
| **Önerilen** | Admin işlemler | Public sayfalar |

---

## ✨ Best Practices

1. **CRUD işlemler için ID kullan**
   ```javascript
   axios.put(`/api/pages/${id}/`, data);
   ```

2. **Public gösterim için slug kullan**
   ```javascript
   axios.get(`/api/pages/slug/${slug}/`);
   ```

3. **PATCH kullan PUT yerine**
   ```javascript
   // ✅ Önerilen
   axios.patch(`/api/pages/${id}/`, { title: 'New' });
   
   // ❌ Gereksiz
   axios.put(`/api/pages/${id}/`, { ...allFields });
   ```

4. **Permission kontrolü view'da**
   ```python
   def get_permissions(self):
       if self.request.method == 'GET':
           return [AllowAny()]
       return [IsAdminUser()]
   ```

---

## 🎨 Pattern Template

İlerde diğer app'ler için bu pattern kullanılabilir:

```python
# urls.py
urlpatterns = [
    path('', ListCreateAPIView.as_view()),           # GET + POST
    path('tree/', TreeAPIView.as_view()),            # Özel endpoint
    path('slug/<slug:slug>/', SlugDetailAPIView.as_view()),  # Slug ile okuma
    path('<int:pk>/', DetailAPIView.as_view()),      # ID ile CRUD
]

# views.py
class ListCreateAPIView(APIView):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [AllowAny()]
    
    def get(self, request):
        # Liste
        pass
    
    def post(self, request):
        # Oluştur
        pass

class DetailAPIView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAdminUser()]
    
    def get(self, request, pk):
        # Detay
        pass
    
    def put(self, request, pk):
        # Tam güncelleme
        pass
    
    def patch(self, request, pk):
        # Kısmi güncelleme
        pass
    
    def delete(self, request, pk):
        # Silme
        pass
```

---

## 📝 Sonuç

✅ RESTful standartlara uygun
✅ ID ve slug desteği
✅ Güvenli ve esnek
✅ Tutarlı yapı
✅ İlerde tüm app'lerde kullanılabilir

Bu pattern ile tüm API'ler standart, güvenli ve kullanışlı olacak! 🚀
