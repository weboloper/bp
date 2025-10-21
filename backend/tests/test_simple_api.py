"""
Basitleştirilmiş API yapısını test etmek için script
"""

import requests
import json


def test_simple_api():
    """
    Basitleştirilmiş API endpoint'lerini test et
    """
    print("=== Basit API Test ===\n")
    
    # 1. API root test
    print("1. API Root:")
    api_root_url = "http://localhost:8000/api/"
    
    try:
        response = requests.get(api_root_url)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        print()
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor!")
        return
    
    # 2. Direct accounts API test
    base_url = "http://localhost:8000/api/accounts"
    
    print("2. Login Endpoint:")
    login_url = f"{base_url}/auth/login/"
    
    response = requests.post(login_url, json={
        "username": "testuser",
        "password": "wrongpass"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("3. Token Verify:")
    verify_url = f"{base_url}/auth/token/verify/"
    
    response = requests.post(verify_url, json={
        "token": "invalid.jwt.token"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("4. Token Refresh:")
    refresh_url = f"{base_url}/auth/token/refresh/"
    
    response = requests.post(refresh_url, json={
        "refresh": "invalid.refresh.token"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("✅ Basit API yapısı çalışıyor!")
    
    print("\n📍 URL Yapısı:")
    print("  📂 /api/                              # API root")
    print("  🔐 /api/accounts/auth/login/          # Login")
    print("  🔄 /api/accounts/auth/token/refresh/  # Refresh")
    print("  ✅ /api/accounts/auth/token/verify/   # Verify")
    
    print("\n🎯 Basitlik Avantajları:")
    print("  ✅ Daha az dosya")
    print("  ✅ Daha az karmaşıklık")
    print("  ✅ Hızlı geliştirme")
    print("  ✅ Kolay debugging")
    print("  📈 İlerde büyütülebilir")
    
    print("\n📋 Frontend Kullanım:")
    print("""
    // Login
    const response = await fetch('/api/accounts/auth/login/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({username, password})
    });
    
    const {access, refresh} = await response.json();
    localStorage.setItem('access_token', access);
    
    // Protected requests
    fetch('/api/protected/', {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
    });
    """)


def test_with_real_user():
    """
    Gerçek user ile test (varsa)
    """
    print("\n=== Gerçek User Test ===\n")
    
    username = input("Username (boş geç): ").strip()
    if not username:
        print("⏭️  Gerçek user test atlandı")
        return
    
    password = input("Password: ").strip()
    if not password:
        print("❌ Password gerekli")
        return
    
    # Login test
    login_url = "http://localhost:8000/api/accounts/auth/login/"
    
    response = requests.post(login_url, json={
        "username": username,
        "password": password
    })
    
    if response.status_code == 200:
        print("✅ Login başarılı!")
        tokens = response.json()
        
        # Token verify test
        verify_url = "http://localhost:8000/api/accounts/auth/token/verify/"
        verify_response = requests.post(verify_url, json={
            "token": tokens['access']
        })
        
        if verify_response.status_code == 200:
            print("✅ Token verify başarılı!")
        else:
            print("❌ Token verify başarısız")
            
        # Refresh test
        refresh_url = "http://localhost:8000/api/accounts/auth/token/refresh/"
        refresh_response = requests.post(refresh_url, json={
            "refresh": tokens['refresh']
        })
        
        if refresh_response.status_code == 200:
            print("✅ Token refresh başarılı!")
            print("🎉 Tüm authentication sistemi çalışıyor!")
        else:
            print("❌ Token refresh başarısız")
    else:
        print("❌ Login başarısız")
        print(f"Error: {response.json()}")


if __name__ == "__main__":
    try:
        test_simple_api()
        test_with_real_user()
    except Exception as e:
        print(f"❌ Hata: {e}")
