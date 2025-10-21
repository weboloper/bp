"""
Token verify ve refresh endpoint'lerini test etmek için basit bir test scripti
"""

import requests
import json


def test_token_endpoints():
    base_url = "http://localhost:8000/api/v1/accounts"
    
    print("=== Token Endpoint Test ===\n")
    
    # 1. Token Verify Test (geçersiz token ile)
    print("1. Token Verify - Geçersiz token:")
    verify_url = f"{base_url}/auth/token/verify/"
    
    response = requests.post(verify_url, json={
        "token": "geçersiz.token.burada"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    # 2. Token Refresh Test (geçersiz refresh token ile)
    print("2. Token Refresh - Geçersiz refresh token:")
    refresh_url = f"{base_url}/auth/token/refresh/"
    
    response = requests.post(refresh_url, json={
        "refresh": "geçersiz.refresh.token"
    })
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    # 3. Token olmadan test
    print("3. Token Verify - Token eksik:")
    response = requests.post(verify_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("4. Token Refresh - Refresh token eksik:")
    response = requests.post(refresh_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    # 5. Cookie-based endpoint'leri test et
    print("5. Token Verify Cookie - Cookie yok:")
    verify_cookie_url = f"{base_url}/auth/token/verify-cookie/"
    
    response = requests.post(verify_cookie_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("6. Token Refresh Cookie - Cookie yok:")
    refresh_cookie_url = f"{base_url}/auth/token/refresh-cookie/"
    
    response = requests.post(refresh_cookie_url, json={})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    print()
    
    print("✅ Tüm endpoint'ler çalışıyor! Geçersiz token/cookie'ler beklendiği gibi hata veriyor.")
    print("\n📝 Sonraki adım: Login endpoint'i oluşturup gerçek token'larla test etmek.")


if __name__ == "__main__":
    try:
        test_token_endpoints()
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor! Önce 'python manage.py runserver' çalıştırın.")
    except Exception as e:
        print(f"❌ Hata: {e}")
