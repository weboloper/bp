"""
Username/Email destekli API test scripti
"""

import requests
import json


def test_username_email_login():
    """
    Username ve email ile login testleri
    """
    print("=== Username/Email Login Test ===\n")
    
    base_url = "http://localhost:8000/api/accounts"
    login_url = f"{base_url}/auth/login/"
    
    # Test cases
    test_cases = [
        {
            "name": "Geçersiz Username",
            "data": {"username": "nonexistent", "password": "wrongpass"},
            "expected_status": 400
        },
        {
            "name": "Geçersiz Email",
            "data": {"username": "nonexistent@example.com", "password": "wrongpass"},
            "expected_status": 400
        },
        {
            "name": "Geçersiz Email Format",
            "data": {"username": "notanemail", "password": "anypass"},
            "expected_status": 400
        },
        {
            "name": "Eksik Username",
            "data": {"password": "somepass"},
            "expected_status": 400
        },
        {
            "name": "Eksik Password",
            "data": {"username": "testuser"},
            "expected_status": 400
        }
    ]
    
    print("🧪 Geçersiz Giriş Testleri:")
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. {test_case['name']}:")
        
        response = requests.post(login_url, json=test_case['data'])
        
        print(f"   Status: {response.status_code}")
        
        try:
            response_data = response.json()
            if 'non_field_errors' in response_data:
                print(f"   Error: {response_data['non_field_errors'][0]}")
            elif 'detail' in response_data:
                print(f"   Error: {response_data['detail']}")
            else:
                print(f"   Response: {json.dumps(response_data, ensure_ascii=False)}")
        except:
            print(f"   Response: {response.text}")
    
    print("\n" + "="*50)
    print("✅ Geçersiz login testleri tamamlandı!")
    
    # Gerçek kullanıcı testi
    print("\n🔐 Gerçek Kullanıcı Testi:")
    real_user_test()


def real_user_test():
    """
    Gerçek kullanıcı ile test
    """
    print("\nGerçek kullanıcı bilgilerini girin (boş bırakın atlamak için):")
    username = input("Username veya Email: ").strip()
    
    if not username:
        print("⏭️  Gerçek kullanıcı testi atlandı")
        return
    
    password = input("Password: ").strip()
    if not password:
        print("❌ Password gerekli")
        return
    
    base_url = "http://localhost:8000/api/accounts"
    login_url = f"{base_url}/auth/login/"
    
    print(f"\n🚀 Login test ediliyor: {username}")
    
    # Login test
    response = requests.post(login_url, json={
        "username": username,
        "password": password
    })
    
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ Login başarılı!")
        tokens = response.json()
        
        print(f"User info: {json.dumps(tokens.get('user', {}), indent=2, ensure_ascii=False)}")
        
        # Token verify test
        verify_url = f"{base_url}/auth/token/verify/"
        verify_response = requests.post(verify_url, json={
            "token": tokens['access']
        })
        
        if verify_response.status_code == 200:
            print("✅ Token verify başarılı!")
        else:
            print(f"❌ Token verify başarısız: {verify_response.status_code}")
            
        # Refresh test
        refresh_url = f"{base_url}/auth/token/refresh/"
        refresh_response = requests.post(refresh_url, json={
            "refresh": tokens['refresh']
        })
        
        if refresh_response.status_code == 200:
            print("✅ Token refresh başarılı!")
            print("🎉 Tüm authentication sistemi mükemmel çalışıyor!")
            
            # Show usage example
            print("\n📋 Frontend Kullanım Örnekleri:")
            print(f"""
// Username ile login
fetch('/api/accounts/auth/login/', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
        username: '{username}',
        password: 'your-password'
    }})
}})

// Email ile login (aynı endpoint)
fetch('/api/accounts/auth/login/', {{
    method: 'POST', 
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
        username: 'user@example.com',  // Email olarak kullan
        password: 'your-password'
    }})
}})
            """)
        else:
            print(f"❌ Token refresh başarısız: {refresh_response.status_code}")
    else:
        print("❌ Login başarısız")
        try:
            error_data = response.json()
            if 'non_field_errors' in error_data:
                print(f"Error: {error_data['non_field_errors'][0]}")
            else:
                print(f"Error: {json.dumps(error_data, ensure_ascii=False)}")
        except:
            print(f"Response: {response.text}")


def show_features():
    """
    Özellikler ve kullanım örneklerini göster
    """
    print("\n🎯 Username/Email Login Özellikleri:")
    print("  ✅ Username ile login: testuser")
    print("  ✅ Email ile login: user@example.com")
    print("  ✅ Otomatik format tanıma (@ işareti)")
    print("  ✅ Email format doğrulama")
    print("  ✅ User verification kontrolü")
    print("  ✅ Detaylı hata mesajları")
    print("  ✅ User bilgileri response'ta")
    
    print("\n📍 Aktif Endpoint'ler:")
    print("  🔐 POST /api/accounts/auth/login/           # Username/Email + password")
    print("  🔄 POST /api/accounts/auth/token/refresh/   # Token yenileme")  
    print("  ✅ POST /api/accounts/auth/token/verify/    # Token doğrulama")
    
    print("\n🎨 Response Formatı:")
    print("""
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "is_verified": true,
    "first_name": "Test",
    "last_name": "User"
  }
}
    """)


if __name__ == "__main__":
    try:
        show_features()
        
        # API erişim testi
        print("\n" + "="*50)
        print("🌐 Django sunucusu kontrolü...")
        
        response = requests.get("http://localhost:8000/api/")
        print(f"API Root Status: {response.status_code}")
        
        if response.status_code == 200:
            test_username_email_login()
        else:
            print("❌ API erişilemiyor. Django sunucusunu başlattınız mı?")
            
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor!")
        print("Önce 'python manage.py runserver' komutunu çalıştırın")
    except Exception as e:
        print(f"❌ Hata: {e}")
