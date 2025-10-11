# Pages API - Özet

## 📁 Oluşturulan Dosya Yapısı

```
pages/
├── api/
│   ├── __init__.py          # Python package
│   ├── serializers.py       # Veri dönüşümü ve validasyon
│   ├── views.py            # API view'ları
│   ├── urls.py             # URL routing
│   └── README.md           # Bu dosya
├── models.py
├── admin.py
└── PAGES_API_DOCUMENTATION.md  # Detaylı dokümantasyon
```

---

## 🎯 RESTful API Endpoints (Standart Pattern)

### Endpoint Yapısı
```
GET    /api/pages/              # Liste (Public)
POST   /api/pages/              # Oluştur (Admin)
GET    /api/pages/<id>/         # ID ile detay (Public)
PUT    /api/pages/<id>/         # ID ile güncelle (Admin)
PATCH  /api/pages/<id>/         # ID ile kısmi güncelle (Admin)
DELETE /api/pages/<id>/         # ID ile sil (Admin)
GET    /api/pages/slug/<slug>/  # Slug ile detay (Public)
GET    /api/pages/tree/         # Tree yapısı (Public)
```

**Önemli:** Permission kontrolü URL'de değil, view'da `permission_classes` ile yapılır.

---

## 🔑 Temel Özellikler

### ID vs Slug
- **ID ile işlemler** (`/api/pages/<id>/`): CRUD işlemleri için (güvenli, değişmez)
- **Slug ile işlemler** (`/api/pages/slug/<slug>/`): Sadece okuma için (SEO-friendly)

### Permission Yapısı
```python
# Public endpoints (GET)
permission_classes = [AllowAny]

# Admin endpoints (POST, PUT, PATCH, DELETE)
permission_classes = [IsAdminUser]
```

View'lar `get_permissions()` metodu ile dinamik permission kontrolü yapar.

---

## 📝 Serializer'lar

### PageListSerializer
Liste görünümü için hafif veri:
- Basic page bilgileri
- Parent başlığı
- Alt sayfa sayısı
- URL

### PageDetailSerializer
Detay görünümü için tam veri:
- Tüm page bilgileri
- Alt sayfalar listesi
- Breadcrumb yolu
- URL

### PageCreateUpdateSerializer
Oluşturma ve güncelleme için:
- Validation kuralları
- Circular reference kontrolü
- Slug uniqueness kontrolü

---

## 🚀 Hızlı Kullanım

### Public Endpoints (Herkes)
```bash
# Liste
curl http://localhost:8000/api/pages/

# ID ile detay
curl http://localhost:8000/api/pages/1/

# Slug ile detay
curl http://localhost:8000/api/pages/slug/hakkimizda/

# Tree yapısı
curl http://localhost:8000/api/pages/tree/

# Filtreleme
curl http://localhost:8000/api/pages/?parent=null
curl http://localhost:8000/api/pages/?search=hakkımızda
```

### Admin Endpoints (JWT Token ile)
```bash
# Oluştur
curl -X POST http://localhost:8000/api/pages/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Test", "slug": "test", "content": "..."}'

# Güncelle (Tam)
curl -X PUT http://localhost:8000/api/pages/1/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated", "slug": "updated", "content": "..."}'

# Güncelle (Kısmi) - Önerilen
curl -X PATCH http://localhost:8000/api/pages/1/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Updated Title"}'

# Sil
curl -X DELETE http://localhost:8000/api/pages/1/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔒 Rate Limiting

| Endpoint | Method | Limit |
|----------|--------|-------|
| `/api/pages/` | GET | 60/min per IP |
| `/api/pages/` | POST | 30/hour per user/IP |
| `/api/pages/<id>/` | GET | 60/min per IP |
| `/api/pages/<id>/` | PUT/PATCH/DELETE | 30/hour per user/IP |
| `/api/pages/slug/<slug>/` | GET | 60/min per IP |
| `/api/pages/tree/` | GET | 60/min per IP |

---

## ⚛️ React Örnek

### ID ile Routing (Önerilen)
```javascript
// Router
<Route path="/pages/:id" element={<PageDetail />} />

// Component
function PageDetail() {
  const { id } = useParams();
  const [page, setPage] = useState(null);

  useEffect(() => {
    axios.get(`http://localhost:8000/api/pages/${id}/`)
      .then(res => setPage(res.data));
  }, [id]);

  return <div>{page?.title}</div>;
}
```

### Slug ile Routing (SEO Friendly)
```javascript
// Router
<Route path="/pages/:slug" element={<PageDetailBySlug />} />

// Component
function PageDetailBySlug() {
  const { slug } = useParams();
  const [page, setPage] = useState(null);

  useEffect(() => {
    axios.get(`http://localhost:8000/api/pages/slug/${slug}/`)
      .then(res => setPage(res.data));
  }, [slug]);

  return <div>{page?.title}</div>;
}
```

---

## 🎨 Design Pattern

### Accounts API ile Aynı Yapı
✅ Aynı klasör organizasyonu (`api/` klasörü)
✅ Aynı dosya isimleri (`serializers.py`, `views.py`, `urls.py`)
✅ APIView sınıfları kullanımı
✅ Rate limiting decorator'ları
✅ Dynamic permission classes
✅ Comprehensive validation
✅ Türkçe hata mesajları
✅ RESTful design principles
✅ app_name convention

### İlerde Diğer App'ler İçin
Bu pattern tüm app'lerde kullanılabilir:
```
/api/<app_name>/              # Liste + Oluştur
/api/<app_name>/<id>/         # CRUD (ID ile)
/api/<app_name>/slug/<slug>/  # Detay (Slug ile)
/api/<app_name>/tree/         # Özel endpoint'ler
```

---

## 📚 Dokümantasyon

Detaylı kullanım için:
- `pages/PAGES_API_DOCUMENTATION.md` - Tam dokümantasyon
- `pages/api/README.md` - Bu dosya (Hızlı başlangıç)

---

## ✅ Advantages

### ID ile İşlemler
✅ Güvenli (değişmez)
✅ Hızlı (primary key)
✅ CRUD işlemleri için ideal
✅ Admin paneller için

### Slug ile İşlemler
✅ SEO-friendly URL'ler
✅ User-friendly
✅ Public sayfalar için ideal
✅ Sadece okuma işlemleri için

### Her İkisi Birden
✅ Esnek kullanım
✅ Frontend'de ihtiyaca göre seçim
✅ Admin/Public ayrımı net

---

## 🔥 Best Practices

1. **Admin işlemler için ID kullan** (güvenli, değişmez)
2. **Public sayfalar için slug kullan** (SEO-friendly)
3. **PATCH kullan PUT yerine** (kısmi güncelleme daha esnek)
4. **Permission kontrolü view'da yap** (URL'de değil)
5. **Rate limiting uygula** (API güvenliği)
6. **Validation kapsamlı yap** (veri bütünlüğü)
7. **Error messages Türkçe** (kullanıcı dostu)

---

## 🚀 Ready to Use

Pages API artık kullanıma hazır! Bu standart pattern ile tüm app'lerde tutarlı API yapısı sağlanır.
