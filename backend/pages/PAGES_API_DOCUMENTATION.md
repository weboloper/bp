# Pages API Kullanım Dokümantasyonu

## API Endpoints

### Public Endpoints (Herkes Erişebilir)

#### 1. Sayfa Listesi
```
GET /api/pages/
```

**Query Parameters:**
- `parent`: Parent ID'ye göre filtrele (örn: `?parent=1` veya `?parent=null`)
- `search`: Başlık veya içeriğe göre ara (örn: `?search=hakkımızda`)

**Örnek İstek:**
```bash
# Tüm sayfaları listele
curl http://localhost:8000/api/pages/

# Ana sayfaları listele (parent olmayan)
curl http://localhost:8000/api/pages/?parent=null

# Belirli bir parent'ın alt sayfalarını listele
curl http://localhost:8000/api/pages/?parent=1

# Arama yap
curl http://localhost:8000/api/pages/?search=hakkımızda
```

**Örnek Response:**
```json
[
  {
    "id": 1,
    "title": "Hakkımızda",
    "slug": "hakkimizda",
    "parent": null,
    "parent_title": null,
    "is_published": true,
    "order": 0,
    "created_at": "2025-10-09T10:00:00Z",
    "updated_at": "2025-10-09T10:00:00Z",
    "children_count": 2,
    "url": "/hakkimizda/"
  }
]
```

#### 2. Sayfa Detayı
```
GET /api/pages/<slug>/
```

**Örnek İstek:**
```bash
curl http://localhost:8000/api/pages/hakkimizda/
```

**Örnek Response:**
```json
{
  "id": 1,
  "title": "Hakkımızda",
  "slug": "hakkimizda",
  "content": "Bu bir test içeriğidir...",
  "parent": null,
  "parent_title": null,
  "is_published": true,
  "order": 0,
  "created_at": "2025-10-09T10:00:00Z",
  "updated_at": "2025-10-09T10:00:00Z",
  "children": [
    {
      "id": 2,
      "title": "Ekibimiz",
      "slug": "ekibimiz",
      "url": "/ekibimiz/",
      "order": 0
    }
  ],
  "breadcrumbs": [
    {
      "id": 1,
      "title": "Hakkımızda",
      "slug": "hakkimizda",
      "url": "/hakkimizda/"
    }
  ],
  "url": "/hakkimizda/"
}
```

#### 3. Sayfa Ağacı (Tree Structure)
```
GET /api/pages/tree/
```

**Örnek İstek:**
```bash
curl http://localhost:8000/api/pages/tree/
```

**Örnek Response:**
```json
[
  {
    "id": 1,
    "title": "Hakkımızda",
    "slug": "hakkimizda",
    "url": "/hakkimizda/",
    "order": 0,
    "children": [
      {
        "id": 2,
        "title": "Ekibimiz",
        "slug": "ekibimiz",
        "url": "/ekibimiz/",
        "order": 0,
        "children": []
      },
      {
        "id": 3,
        "title": "Misyonumuz",
        "slug": "misyonumuz",
        "url": "/misyonumuz/",
        "order": 1,
        "children": []
      }
    ]
  },
  {
    "id": 4,
    "title": "İletişim",
    "slug": "iletisim",
    "url": "/iletisim/",
    "order": 1,
    "children": []
  }
]
```

---

### Admin Endpoints (Sadece Admin Kullanıcılar)

#### 4. Sayfa Oluşturma
```
POST /api/pages/admin/create/
```

**Authentication:** JWT Token gerekli (Admin)

**Örnek İstek:**
```bash
curl -X POST http://localhost:8000/api/pages/admin/create/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Yeni Sayfa",
    "slug": "yeni-sayfa",
    "content": "Sayfa içeriği buraya gelecek...",
    "parent": null,
    "is_published": true,
    "order": 0
  }'
```

**Request Body:**
```json
{
  "title": "Yeni Sayfa",
  "slug": "yeni-sayfa",
  "content": "Sayfa içeriği buraya gelecek...",
  "parent": null,
  "is_published": true,
  "order": 0
}
```

**Response:** Oluşturulan sayfa detayı (PageDetailSerializer formatında)

#### 5. Sayfa Güncelleme (Tam)
```
PUT /api/pages/admin/<slug>/update/
```

**Authentication:** JWT Token gerekli (Admin)

**Örnek İstek:**
```bash
curl -X PUT http://localhost:8000/api/pages/admin/yeni-sayfa/update/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Güncellenmiş Sayfa",
    "slug": "guncellenmis-sayfa",
    "content": "Güncellenmiş içerik...",
    "parent": null,
    "is_published": true,
    "order": 0
  }'
```

#### 6. Sayfa Güncelleme (Kısmi)
```
PATCH /api/pages/admin/<slug>/update/
```

**Authentication:** JWT Token gerekli (Admin)

**Örnek İstek:**
```bash
# Sadece başlığı güncelle
curl -X PATCH http://localhost:8000/api/pages/admin/yeni-sayfa/update/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Yeni Başlık"
  }'

# Sadece içeriği güncelle
curl -X PATCH http://localhost:8000/api/pages/admin/yeni-sayfa/update/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Yeni içerik..."
  }'
```

#### 7. Sayfa Silme
```
DELETE /api/pages/admin/<slug>/delete/
```

**Authentication:** JWT Token gerekli (Admin)

**Örnek İstek:**
```bash
curl -X DELETE http://localhost:8000/api/pages/admin/yeni-sayfa/delete/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "detail": "\"Yeni Sayfa\" sayfası başarıyla silindi"
}
```

---

## Rate Limiting

- **Public Endpoints (GET):** 60 requests/minute per IP
- **Admin Create/Update:** 30 requests/hour per user or IP
- **Admin Delete:** 10 requests/hour per user or IP

---

## Hata Mesajları

### Validation Errors (400)
```json
{
  "title": ["Başlık en az 3 karakter olmalı"],
  "slug": ["Bu slug zaten kullanılıyor"],
  "content": ["İçerik gerekli"]
}
```

### Not Found (404)
```json
{
  "detail": "Not found."
}
```

### Permission Denied (403)
```json
{
  "detail": "You do not have permission to perform this action."
}
```

### Server Error (500)
```json
{
  "detail": "Sayfa oluşturulurken bir hata oluştu"
}
```

---

## JavaScript Örnekleri

### Fetch ile Sayfa Listesi
```javascript
// Tüm sayfaları getir
fetch('http://localhost:8000/api/pages/')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));

// Ana sayfaları getir
fetch('http://localhost:8000/api/pages/?parent=null')
  .then(response => response.json())
  .then(data => console.log(data));

// Arama yap
fetch('http://localhost:8000/api/pages/?search=hakkımızda')
  .then(response => response.json())
  .then(data => console.log(data));
```

### Fetch ile Sayfa Detayı
```javascript
fetch('http://localhost:8000/api/pages/hakkimizda/')
  .then(response => response.json())
  .then(data => {
    console.log('Sayfa:', data.title);
    console.log('İçerik:', data.content);
    console.log('Alt Sayfalar:', data.children);
  });
```

### Fetch ile Sayfa Ağacı
```javascript
fetch('http://localhost:8000/api/pages/tree/')
  .then(response => response.json())
  .then(tree => {
    // Tree yapısını render et
    renderTree(tree);
  });

function renderTree(tree, level = 0) {
  tree.forEach(node => {
    console.log('  '.repeat(level) + node.title);
    if (node.children.length > 0) {
      renderTree(node.children, level + 1);
    }
  });
}
```

### Axios ile Sayfa Oluşturma (Admin)
```javascript
const token = 'YOUR_ACCESS_TOKEN';

axios.post('http://localhost:8000/api/pages/admin/create/', {
  title: 'Yeni Sayfa',
  slug: 'yeni-sayfa',
  content: 'İçerik...',
  parent: null,
  is_published: true,
  order: 0
}, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
})
.then(response => {
  console.log('Sayfa oluşturuldu:', response.data);
})
.catch(error => {
  console.error('Hata:', error.response.data);
});
```

### Axios ile Sayfa Güncelleme (Admin)
```javascript
const token = 'YOUR_ACCESS_TOKEN';

// Tam güncelleme (PUT)
axios.put('http://localhost:8000/api/pages/admin/yeni-sayfa/update/', {
  title: 'Güncellenmiş Başlık',
  slug: 'guncellenmis-baslik',
  content: 'Güncellenmiş içerik...',
  parent: null,
  is_published: true,
  order: 0
}, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
})
.then(response => console.log('Güncellendi:', response.data))
.catch(error => console.error('Hata:', error.response.data));

// Kısmi güncelleme (PATCH)
axios.patch('http://localhost:8000/api/pages/admin/yeni-sayfa/update/', {
  title: 'Sadece Başlık Güncellendi'
}, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
})
.then(response => console.log('Güncellendi:', response.data))
.catch(error => console.error('Hata:', error.response.data));
```

### Axios ile Sayfa Silme (Admin)
```javascript
const token = 'YOUR_ACCESS_TOKEN';

axios.delete('http://localhost:8000/api/pages/admin/yeni-sayfa/delete/', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})
.then(response => {
  console.log(response.data.detail);
})
.catch(error => {
  console.error('Hata:', error.response.data);
});
```

---

## React Örnek Kullanım

### Sayfa Listesi Component
```javascript
import React, { useState, useEffect } from 'react';
import axios from 'axios';

function PageList() {
  const [pages, setPages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get('http://localhost:8000/api/pages/')
      .then(response => {
        setPages(response.data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Yükleniyor...</div>;
  if (error) return <div>Hata: {error}</div>;

  return (
    <div>
      <h1>Sayfalar</h1>
      <ul>
        {pages.map(page => (
          <li key={page.id}>
            <a href={page.url}>{page.title}</a>
            <span> ({page.children_count} alt sayfa)</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default PageList;
```

### Sayfa Detay Component
```javascript
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

function PageDetail() {
  const { slug } = useParams();
  const [page, setPage] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`http://localhost:8000/api/pages/${slug}/`)
      .then(response => {
        setPage(response.data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, [slug]);

  if (loading) return <div>Yükleniyor...</div>;
  if (!page) return <div>Sayfa bulunamadı</div>;

  return (
    <div>
      <nav>
        {page.breadcrumbs.map((crumb, index) => (
          <span key={crumb.id}>
            {index > 0 && ' > '}
            <a href={crumb.url}>{crumb.title}</a>
          </span>
        ))}
      </nav>
      
      <h1>{page.title}</h1>
      <div dangerouslySetInnerHTML={{ __html: page.content }} />
      
      {page.children.length > 0 && (
        <div>
          <h2>Alt Sayfalar</h2>
          <ul>
            {page.children.map(child => (
              <li key={child.id}>
                <a href={child.url}>{child.title}</a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default PageDetail;
```

### Sayfa Oluşturma Form (Admin)
```javascript
import React, { useState } from 'react';
import axios from 'axios';

function PageCreateForm({ token }) {
  const [formData, setFormData] = useState({
    title: '',
    slug: '',
    content: '',
    parent: null,
    is_published: true,
    order: 0
  });
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    try {
      const response = await axios.post(
        'http://localhost:8000/api/pages/admin/create/',
        formData,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        }
      );
      
      setSuccess(true);
      console.log('Sayfa oluşturuldu:', response.data);
      
      // Form'u temizle
      setFormData({
        title: '',
        slug: '',
        content: '',
        parent: null,
        is_published: true,
        order: 0
      });
    } catch (err) {
      setError(err.response?.data || 'Bir hata oluştu');
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Yeni Sayfa Oluştur</h2>
      
      {error && (
        <div style={{ color: 'red' }}>
          {JSON.stringify(error)}
        </div>
      )}
      
      {success && (
        <div style={{ color: 'green' }}>
          Sayfa başarıyla oluşturuldu!
        </div>
      )}

      <div>
        <label>Başlık:</label>
        <input
          type="text"
          name="title"
          value={formData.title}
          onChange={handleChange}
          required
        />
      </div>

      <div>
        <label>Slug:</label>
        <input
          type="text"
          name="slug"
          value={formData.slug}
          onChange={handleChange}
          required
        />
      </div>

      <div>
        <label>İçerik:</label>
        <textarea
          name="content"
          value={formData.content}
          onChange={handleChange}
          required
          rows="10"
        />
      </div>

      <div>
        <label>Sıralama:</label>
        <input
          type="number"
          name="order"
          value={formData.order}
          onChange={handleChange}
        />
      </div>

      <div>
        <label>
          <input
            type="checkbox"
            name="is_published"
            checked={formData.is_published}
            onChange={handleChange}
          />
          Yayınlanmış
        </label>
      </div>

      <button type="submit">Oluştur</button>
    </form>
  );
}

export default PageCreateForm;
```

---

## Özellikler

### Accounts API ile Aynı Yapı
✅ Aynı klasör yapısı (`api/` klasörü içinde)
✅ `serializers.py` - Veri dönüşümü ve validasyon
✅ `views.py` - API view'ları
✅ `urls.py` - URL routing
✅ `__init__.py` - Python package yapısı

### Best Practices
✅ Rate limiting (API kötüye kullanımını önler)
✅ Permission classes (Public/Admin ayrımı)
✅ Comprehensive validation (Tüm veri doğrulama)
✅ Detailed error messages (Türkçe hata mesajları)
✅ RESTful design (Standart HTTP metodları)
✅ Query parameters (Filtreleme ve arama)

### Güvenlik Özellikleri
✅ JWT Authentication (Admin endpoints için)
✅ Rate limiting (Tüm endpoints)
✅ Permission checks (IsAuthenticated, IsAdminUser)
✅ Circular reference prevention (Parent-child ilişkilerinde)
✅ Slug uniqueness validation

---

## Test Etme

### Public Endpoints Test
```bash
# Tüm sayfaları listele
curl http://localhost:8000/api/pages/

# Belirli bir sayfayı getir
curl http://localhost:8000/api/pages/hakkimizda/

# Tree yapısını getir
curl http://localhost:8000/api/pages/tree/
```

### Admin Endpoints Test (JWT Token ile)
```bash
# Önce login olup token al
curl -X POST http://localhost:8000/api/accounts/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'

# Token'ı kullanarak sayfa oluştur
curl -X POST http://localhost:8000/api/pages/admin/create/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Sayfası",
    "slug": "test-sayfasi",
    "content": "Test içeriği...",
    "is_published": true,
    "order": 0
  }'
```
