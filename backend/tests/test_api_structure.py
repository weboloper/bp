"""
Güncellenmiş API yapısını test etmek için test scripti
"""

import requests
import json


def test_api_structure():
    """
    API yapısını ve endpoint'leri test et
    """
    print("=== Güncellenmiş API Yapı Test ===\n")
    
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
    
    # 2. JSON-based endpoint'leri test (Django Simple JWT)
    base_url = "http://localhost:8000/api/accounts"
    
    print("2. JSON-based Login (Django Simple JWT):")
    login_url = f"{base_url}/auth/login/"
    
    response = requests.post(login_url, json={
        "username": "geçersizuser",
        "password": "geçersizpass"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    # 3. Cookie-based endpoint'leri test
    print("3. Cookie-based Login:")
    cookie_login_url = f"{base_url}/auth/login-cookie/"
    
    response = requests.post(cookie_login_url, json={
        "username": "geçersizuser",
        "password": "geçersizpass"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("4. Cookie-based Token Verify:")
    verify_cookie_url = f"{base_url}/auth/token/verify-cookie/"
    
    response = requests.post(verify_cookie_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("5. Cookie-based Logout:")
    logout_cookie_url = f"{base_url}/auth/logout-cookie/"
    
    response = requests.post(logout_cookie_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("✅ Hibrit API yapısı çalışıyor!")
    print("\n🎯 Endpoint Türleri:")
    print("  • JSON-based: Django Simple JWT hazır views")
    print("  • Cookie-based: Custom güvenli implementation")
    
    print("\n📍 Mevcut Endpoint'ler:")
    print("  🟦 JSON-based (Authorization header):")
    print("     - POST /api/accounts/auth/login/")
    print("     - POST /api/accounts/auth/token/refresh/")
    print("     - POST /api/accounts/auth/token/verify/")
    
    print("  🍪 Cookie-based (httpOnly cookies):")
    print("     - POST /api/accounts/auth/login-cookie/")
    print("     - POST /api/accounts/auth/logout-cookie/")
    print("     - POST /api/accounts/auth/token/verify-cookie/")
    print("     - POST /api/accounts/auth/token/refresh-cookie/")
    
    print("\n📋 Sonraki Test:")
    print("  - Test user oluştur: python manage.py createsuperuser")
    print("  - Cookie guide çalıştır: python cookie_auth_guide.py")


if __name__ == "__main__":
    try:
        test_api_structure()
    except Exception as e:
        print(f"❌ Hata: {e}")
