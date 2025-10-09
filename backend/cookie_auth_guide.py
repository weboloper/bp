"""
Cookie-based Authentication Endpoint'lerinin Kullanımı
=====================================================

Bu döküman cookie-based authentication endpoint'lerinin nasıl kullanılacağını açıklar.
"""

import requests
import json

# Base URL
BASE_URL = "http://localhost:8000/api/accounts"

def demo_cookie_authentication():
    """
    Cookie-based authentication akışını gösterir
    """
    # Session oluştur - cookie'leri otomatik yönetir
    session = requests.Session()
    
    print("=== Cookie-Based Authentication Demo ===\n")
    
    # 1. LOGIN - Cookie'leri alır
    print("1️⃣  LOGIN:")
    print("POST /api/accounts/auth/login-cookie/")
    print("Body: {username, password}")
    
    login_response = session.post(f"{BASE_URL}/auth/login-cookie/", json={
        "username": "testuser",  # Değiştir
        "password": "testpass123"  # Değiştir
    })
    
    print(f"Status: {login_response.status_code}")
    if login_response.status_code == 200:
        print("✅ Login başarılı!")
        print(f"Response: {json.dumps(login_response.json(), indent=2, ensure_ascii=False)}")
        print(f"Set-Cookie headers: {login_response.headers.get('Set-Cookie', 'Yok')}")
        
        # 2. TOKEN VERIFY - Cookie'den token'ı kontrol eder
        print("\n2️⃣  TOKEN VERIFY (Cookie):")
        print("POST /api/accounts/auth/token/verify-cookie/")
        print("Body: {} (Cookie'den otomatik alır)")
        
        verify_response = session.post(f"{BASE_URL}/auth/token/verify-cookie/", json={})
        print(f"Status: {verify_response.status_code}")
        print(f"Response: {json.dumps(verify_response.json(), indent=2, ensure_ascii=False)}")
        
        # 3. TOKEN REFRESH - Cookie'deki refresh token ile access token yeniler
        print("\n3️⃣  TOKEN REFRESH (Cookie):")
        print("POST /api/accounts/auth/token/refresh-cookie/")
        print("Body: {} (Refresh cookie'den otomatik alır)")
        
        refresh_response = session.post(f"{BASE_URL}/auth/token/refresh-cookie/", json={})
        print(f"Status: {refresh_response.status_code}")
        print(f"Response: {json.dumps(refresh_response.json(), indent=2, ensure_ascii=False)}")
        
        # 4. LOGOUT - Cookie'leri temizler
        print("\n4️⃣  LOGOUT:")
        print("POST /api/accounts/auth/logout-cookie/")
        print("Body: {}")
        
        logout_response = session.post(f"{BASE_URL}/auth/logout-cookie/", json={})
        print(f"Status: {logout_response.status_code}")
        print(f"Response: {json.dumps(logout_response.json(), indent=2, ensure_ascii=False)}")
        
        # 5. LOGOUT SONRASI VERIFY - Artık token geçersiz olmalı
        print("\n5️⃣  VERIFY AFTER LOGOUT:")
        print("POST /api/accounts/auth/token/verify-cookie/")
        
        verify_after_logout = session.post(f"{BASE_URL}/auth/token/verify-cookie/", json={})
        print(f"Status: {verify_after_logout.status_code}")
        print(f"Response: {json.dumps(verify_after_logout.json(), indent=2, ensure_ascii=False)}")
        
    else:
        print("❌ Login başarısız!")
        print(f"Error: {json.dumps(login_response.json(), indent=2, ensure_ascii=False)}")


def compare_json_vs_cookie():
    """
    JSON-based vs Cookie-based endpoint'lerin karşılaştırması
    """
    print("\n=== JSON vs Cookie Karşılaştırması ===\n")
    
    print("📝 JSON-based (Geleneksel):")
    print("   - Frontend token'ları localStorage'da tutar")
    print("   - Her request'te Authorization header'ı ekler")
    print("   - XSS saldırılarına açık")
    print("   - Manuel token yönetimi gerekli")
    print("   URLs:")
    print("     • POST /api/accounts/auth/login/ (Django Simple JWT)")
    print("     • POST /api/accounts/auth/token/refresh/ (Django Simple JWT)")
    print("     • POST /api/accounts/auth/token/verify/ (Django Simple JWT)")
    
    print("\n🍪 Cookie-based (Güvenli):")
    print("   - Token'lar httpOnly cookie'lerde saklanır")
    print("   - Browser otomatik olarak cookie'leri gönderir")
    print("   - XSS saldırılarına karşı korumalı")
    print("   - CSRF token ile ek güvenlik")
    print("   URLs:")
    print("     • POST /api/accounts/auth/login-cookie/")
    print("     • POST /api/accounts/auth/logout-cookie/")
    print("     • POST /api/accounts/auth/token/verify-cookie/")
    print("     • POST /api/accounts/auth/token/refresh-cookie/")


def frontend_usage_examples():
    """
    Frontend'de kullanım örnekleri
    """
    print("\n=== Frontend Kullanım Örnekleri ===\n")
    
    print("🟦 JavaScript Fetch API:")
    print('''
// Login
const loginResponse = await fetch('/api/accounts/auth/login-cookie/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')  // CSRF token
    },
    credentials: 'include',  // Cookie'leri dahil et
    body: JSON.stringify({
        username: 'testuser',
        password: 'testpass123'
    })
});

// Token verify (Cookie otomatik gönderilir)
const verifyResponse = await fetch('/api/accounts/auth/token/verify-cookie/', {
    method: 'POST',
    headers: {
        'X-CSRFToken': getCookie('csrftoken')
    },
    credentials: 'include'
});

// Logout
const logoutResponse = await fetch('/api/accounts/auth/logout-cookie/', {
    method: 'POST',
    headers: {
        'X-CSRFToken': getCookie('csrftoken')
    },
    credentials: 'include'
});
''')
    
    print("\n🟩 React/Next.js Örneği:")
    print('''
// API Service
class AuthService {
    async login(username, password) {
        const response = await fetch('/api/accounts/auth/login-cookie/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCSRFToken()
            },
            credentials: 'include',
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            return data.user;
        }
        throw new Error('Login failed');
    }
    
    async logout() {
        await fetch('/api/accounts/auth/logout-cookie/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.getCSRFToken()
            },
            credentials: 'include'
        });
    }
    
    async verifyToken() {
        const response = await fetch('/api/accounts/auth/token/verify-cookie/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.getCSRFToken()
            },
            credentials: 'include'
        });
        return response.ok;
    }
}
''')


def security_notes():
    """
    Güvenlik notları
    """
    print("\n=== Güvenlik Notları ===\n")
    
    print("🔒 Cookie Güvenlik Ayarları:")
    print("   • httpOnly=True: JavaScript erişimi engellenir")
    print("   • secure=True: Sadece HTTPS'de gönderilir (production)")
    print("   • samesite='Lax': CSRF koruması")
    print("   • Max-Age: Token süreleri ayarlanır")
    
    print("\n🛡️  CSRF Koruması:")
    print("   • Django CSRF middleware aktif olmalı")
    print("   • Frontend her POST request'te CSRF token göndermeli")
    print("   • X-CSRFToken header'ı kullan")
    
    print("\n⚠️  Önemli Notlar:")
    print("   • Development'ta secure=False, production'da secure=True")
    print("   • CORS ayarları cookie'ler için credentials=True olmalı")
    print("   • Subdomain'ler arası çalışması için domain ayarları gerekli")


if __name__ == "__main__":
    try:
        compare_json_vs_cookie()
        frontend_usage_examples()
        security_notes()
        
        print("\n" + "="*50)
        print("🚀 TEST ETMEK İÇİN:")
        print("1. Django sunucusunu başlat: python manage.py runserver")
        print("2. Test user oluştur: python manage.py createsuperuser")
        print("3. Bu script'i çalıştır: python cookie_auth_guide.py")
        print("="*50)
        
        # Gerçek test (sadece server çalışıyorsa)
        print("\nGerçek test denemesi...")
        demo_cookie_authentication()
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Django sunucusu çalışmıyor!")
        print("Önce 'python manage.py runserver' komutunu çalıştırın")
    except Exception as e:
        print(f"\n❌ Hata: {e}")
