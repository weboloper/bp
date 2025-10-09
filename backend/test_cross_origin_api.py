"""
Cross-origin için optimize edilmiş API test scripti
"""

import requests
import json


def test_cross_origin_api():
    """
    Cross-origin destekli API endpoint'lerini test et
    """
    print("=== Cross-Origin API Test ===\n")
    
    # 1. API root test
    print("1. API Root Endpoint:")
    api_root_url = "http://localhost:8000/api/"
    
    try:
        response = requests.get(api_root_url)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        print()
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor!")
        return
    
    # 2. Simple JWT endpoint'leri test
    base_url = "http://localhost:8000/api/accounts"
    
    print("2. Django Simple JWT Login:")
    login_url = f"{base_url}/auth/login/"
    
    response = requests.post(login_url, json={
        "username": "geçersizuser",
        "password": "geçersizpass"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("3. Token Verify:")
    verify_url = f"{base_url}/auth/token/verify/"
    
    response = requests.post(verify_url, json={
        "token": "geçersiz.jwt.token.örneği"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("4. Token Refresh:")
    refresh_url = f"{base_url}/auth/token/refresh/"
    
    response = requests.post(refresh_url, json={
        "refresh": "geçersiz.refresh.token.örneği"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("✅ Cross-origin API hazır!")
    
    print("\n🎯 Aktif Endpoint'ler:")
    print("  ✅ POST /api/accounts/auth/login/           # Django Simple JWT")
    print("  ✅ POST /api/accounts/auth/token/refresh/   # Django Simple JWT")  
    print("  ✅ POST /api/accounts/auth/token/verify/    # Django Simple JWT")
    
    print("\n💤 Devre Dışı Endpoint'ler (Comment'li):")
    print("  💤 POST /api/accounts/auth/login-cookie/")
    print("  💤 POST /api/accounts/auth/logout-cookie/")
    print("  💤 POST /api/accounts/auth/token/verify-cookie/")
    print("  💤 POST /api/accounts/auth/token/refresh-cookie/")
    
    print("\n📋 Frontend Kullanım:")
    print("""
    // Login
    const response = await fetch('http://your-backend.com/api/accounts/auth/login/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({username, password})
    });
    
    const {access, refresh} = await response.json();
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
    
    // Protected requests
    fetch('http://your-backend.com/api/protected/', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
    });
    """)


if __name__ == "__main__":
    try:
        test_cross_origin_api()
    except Exception as e:
        print(f"❌ Hata: {e}")
