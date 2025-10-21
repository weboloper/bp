"""
/me endpoint test scripti - JWT authentication
"""

import requests
import json


def test_me_endpoint():
    """
    /me endpoint'ini test et
    """
    print("=== /me Endpoint Test ===\n")
    
    base_url = "http://localhost:8000/api/accounts"
    login_url = f"{base_url}/auth/login/"
    me_url = f"{base_url}/me/"
    
    # 1. Önce authentication olmadan dene
    print("1. Unauthenticated Request:")
    response = requests.get(me_url)
    
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    except:
        print(f"Response: {response.text}")
    print()
    
    # 2. Login yaparak token al
    print("2. Login to Get Token:")
    username = input("Username veya Email: ").strip()
    
    if not username:
        print("⏭️  Login testi atlandı")
        return
    
    password = input("Password: ").strip()
    if not password:
        print("❌ Password gerekli")
        return
    
    # Login request
    login_response = requests.post(login_url, json={
        "username": username,
        "password": password
    })
    
    print(f"Login Status: {login_response.status_code}")
    
    if login_response.status_code == 200:
        tokens = login_response.json()
        print("✅ Login başarılı!")
        print(f"Tokens: {json.dumps(tokens, indent=2)}")
        print()
        
        # 3. Access token ile /me endpoint'ine istek at
        print("3. Authenticated /me Request:")
        
        headers = {
            'Authorization': f'Bearer {tokens["access"]}'
        }
        
        me_response = requests.get(me_url, headers=headers)
        
        print(f"Status: {me_response.status_code}")
        
        if me_response.status_code == 200:
            user_data = me_response.json()
            print("✅ /me endpoint başarılı!")
            print(f"User Data: {json.dumps(user_data, indent=2, ensure_ascii=False, default=str)}")
            
            # 4. Invalid token test
            print("\n4. Invalid Token Test:")
            invalid_headers = {
                'Authorization': 'Bearer invalid.token.here'
            }
            
            invalid_response = requests.get(me_url, headers=invalid_headers)
            print(f"Status: {invalid_response.status_code}")
            try:
                print(f"Response: {json.dumps(invalid_response.json(), indent=2, ensure_ascii=False)}")
            except:
                print(f"Response: {invalid_response.text}")
            
            # 5. Frontend kullanım örneği göster
            print("\n📋 Frontend Kullanım Örneği:")
            print(f"""
// 1. Login
const loginResponse = await fetch('/api/accounts/auth/login/', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
        username: '{username}',
        password: 'your-password'
    }})
}});

const tokens = await loginResponse.json();
localStorage.setItem('access_token', tokens.access);
localStorage.setItem('refresh_token', tokens.refresh);

// 2. Get user profile
const userResponse = await fetch('/api/accounts/me/', {{
    headers: {{
        'Authorization': `Bearer ${{localStorage.getItem('access_token')}}`
    }}
}});

const userData = await userResponse.json();
console.log('Current user:', userData);
            """)
            
            print("\n🎯 Endpoint Özellikleri:")
            print("  ✅ JWT authentication gerekli")
            print("  ✅ Full user profile + profil bilgileri")
            print("  ✅ Avatar URL (varsa)")
            print("  ✅ Timestamps (date_joined, last_login)")
            print("  ✅ Verification status")
            
        else:
            print("❌ /me endpoint başarısız")
            try:
                print(f"Error: {json.dumps(me_response.json(), indent=2, ensure_ascii=False)}")
            except:
                print(f"Response: {me_response.text}")
                
    else:
        print("❌ Login başarısız")
        try:
            error_data = login_response.json()
            print(f"Error: {json.dumps(error_data, ensure_ascii=False)}")
        except:
            print(f"Response: {login_response.text}")


def show_api_overview():
    """
    API yapısını göster
    """
    print("🎯 Modern Auth API Yapısı:")
    print("  🔐 POST /api/accounts/auth/login/     # Username/Email + Password → Tokens")
    print("  👤 GET  /api/accounts/me/             # JWT → User Profile")
    print("  🔄 POST /api/accounts/auth/token/refresh/  # Refresh token")
    print("  ✅ POST /api/accounts/auth/token/verify/   # Token verify")
    
    print("\n📋 Authentication Flow:")
    print("  1. Login → Get access & refresh tokens")
    print("  2. Store tokens (localStorage/secure storage)")
    print("  3. Use access token for protected endpoints")
    print("  4. Refresh when access token expires")
    
    print("\n🔒 /me Endpoint Response:")
    print("""
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "first_name": "Test",
  "last_name": "User",
  "is_active": true,
  "is_verified": true,
  "date_joined": "2024-01-01T12:00:00Z",
  "last_login": "2024-01-02T08:30:00Z",
  "profile": {
    "birth_date": "1990-01-01",
    "bio": "Hello world!",
    "avatar": "/media/avatars/user.jpg",
    "created_at": "2024-01-01T12:01:00Z",
    "updated_at": "2024-01-02T10:15:00Z"
  }
}
    """)


if __name__ == "__main__":
    try:
        show_api_overview()
        
        print("\n" + "="*50)
        print("🌐 Django sunucusu kontrolü...")
        
        response = requests.get("http://localhost:8000/api/")
        print(f"API Root Status: {response.status_code}")
        
        if response.status_code == 200:
            test_me_endpoint()
        else:
            print("❌ API erişilemiyor. Django sunucusunu başlattınız mı?")
            
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor!")
        print("Önce 'python manage.py runserver' komutunu çalıştırın")
    except Exception as e:
        print(f"❌ Hata: {e}")
