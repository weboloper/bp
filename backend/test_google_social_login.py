"""
Google Social Login API Test Script
"""

import requests
import json


def test_google_social_login():
    """
    Google Social Login endpoint'ini test et
    """
    print("=== Google Social Login API Test ===\n")
    
    base_url = "http://localhost:8000/api/accounts"
    google_login_url = f"{base_url}/auth/social/google/"
    
    print("🔍 Google Social Login Endpoint'i test ediliyor...")
    print(f"URL: {google_login_url}")
    print()
    
    # Test cases
    test_cases = [
        {
            'name': 'Boş access_token',
            'data': {}
        },
        {
            'name': 'Geçersiz access_token',
            'data': {'access_token': 'invalid_token_12345'}
        },
        {
            'name': 'Boş string access_token',
            'data': {'access_token': ''}
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"{i}. {test_case['name']}:")
        
        try:
            response = requests.post(google_login_url, json=test_case['data'])
            
            print(f"   Status: {response.status_code}")
            
            try:
                response_data = response.json()
                print(f"   Response: {json.dumps(response_data, indent=4, ensure_ascii=False)}")
            except:
                print(f"   Response: {response.text}")
                
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
    
    # Real Google token test
    print("🎯 Gerçek Google Token Testi:")
    print("Bu test için geçerli bir Google OAuth access token gerekli.")
    print("Frontend'de Google OAuth2 flow'unu tamamladıktan sonra buraya token ekleyiniz.")
    
    # Google token input (gerçek test için)
    google_token = input("\nGoogle Access Token (opsiyonel, Enter ile geç): ").strip()
    
    if google_token:
        print(f"\n🔐 Gerçek Google token ile test ediliyor...")
        
        try:
            response = requests.post(google_login_url, json={
                'access_token': google_token
            })
            
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                tokens = response.json()
                print("✅ Google Social Login başarılı!")
                print(f"Response: {json.dumps(tokens, indent=2)}")
                
                # Token ile /me endpoint'i test et
                print(f"\n🔍 JWT token ile /me endpoint'i test ediliyor...")
                
                me_url = f"{base_url}/me/"
                me_response = requests.get(me_url, headers={
                    'Authorization': f'Bearer {tokens["access"]}'
                })
                
                print(f"Status: {me_response.status_code}")
                
                if me_response.status_code == 200:
                    user_data = me_response.json()
                    print("✅ /me endpoint başarılı!")
                    print(f"User Data: {json.dumps(user_data, indent=2, ensure_ascii=False, default=str)}")
                else:
                    print("❌ /me endpoint başarısız")
                    try:
                        print(f"Error: {me_response.json()}")
                    except:
                        print(f"Response: {me_response.text}")
                
            else:
                print("❌ Google Social Login başarısız")
                try:
                    error_data = response.json()
                    print(f"Error: {json.dumps(error_data, indent=2, ensure_ascii=False)}")
                except:
                    print(f"Response: {response.text}")
                    
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("⏭️  Gerçek token testi atlandı")


def show_google_integration_info():
    """
    Google OAuth2 entegrasyon bilgilerini göster
    """
    print("🎯 Google Social Login Integration:")
    print("  📍 POST /api/accounts/auth/social/google/")
    
    print("\n📋 Request Format:")
    print("""
{
  "access_token": "ya29.a0AfH6SMC..."
}
    """)
    
    print("✅ Success Response (200):")
    print("""
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
    """)
    
    print("❌ Error Response (400):")
    print("""
{
  "access_token": ["Google access token gerekli"]
}

{
  "detail": "Geçersiz Google access token"
}
    """)
    
    print("🔧 Frontend Integration:")
    print("""
// 1. Google OAuth2 ile access token al
const googleAuth = await google.accounts.oauth2.initTokenClient({
    client_id: 'YOUR_GOOGLE_CLIENT_ID',
    scope: 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
    callback: (tokenResponse) => {
        handleGoogleLogin(tokenResponse.access_token);
    }
});

// 2. Backend'e access token gönder
const handleGoogleLogin = async (googleAccessToken) => {
    try {
        const response = await fetch('/api/accounts/auth/social/google/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                access_token: googleAccessToken
            })
        });
        
        if (response.ok) {
            const tokens = await response.json();
            
            // JWT tokens'ı sakla
            localStorage.setItem('access_token', tokens.access);
            localStorage.setItem('refresh_token', tokens.refresh);
            
            // User'ı login et
            window.location.href = '/dashboard';
        }
    } catch (error) {
        console.error('Google login failed:', error);
    }
};
    """)
    
    print("\n🔑 Google OAuth2 Setup (Console):")
    print("  1. https://console.developers.google.com")
    print("  2. Create project → Enable Google+ API")
    print("  3. Create OAuth2 credentials")
    print("  4. Add authorized origins/redirect URIs")
    print("  5. Get CLIENT_ID for frontend")


def show_user_creation_flow():
    """
    User oluşturma flow'unu açıkla
    """
    print("\n🧑‍💻 User Creation Flow:")
    print("  1. Google token verify edilir")
    print("  2. Email ile mevcut user aranır")
    print("  3a. User varsa → Google bilgileri güncellenir")
    print("  3b. User yoksa → Yeni user oluşturulur")
    print("  4. is_verified = True (Google verified)")
    print("  5. Profile oluşturulur")
    print("  6. Google avatar indirilmeye çalışılır")
    print("  7. JWT tokens oluşturulur")
    
    print("\n📝 User Fields:")
    print("  • username: email@domain → domain (unique suffix eklenir)")
    print("  • email: Google'dan gelen email")
    print("  • first_name: Google given_name")
    print("  • last_name: Google family_name")
    print("  • is_verified: True (Google verified)")
    print("  • profile.bio: 'Google ile kayıt oldu'")
    print("  • profile.avatar: Google picture (if available)")


if __name__ == "__main__":
    try:
        show_google_integration_info()
        show_user_creation_flow()
        
        print("\n" + "="*60)
        print("🌐 Django sunucusu kontrolü...")
        
        response = requests.get("http://localhost:8000/api/")
        print(f"API Root Status: {response.status_code}")
        
        if response.status_code == 200:
            test_google_social_login()
        else:
            print("❌ API erişilemiyor. Django sunucusunu başlattınız mı?")
            
    except requests.exceptions.ConnectionError:
        print("❌ Django sunucusu çalışmıyor!")
        print("Önce 'python manage.py runserver' komutunu çalıştırın")
        print("Ve 'pip install google-auth google-auth-oauthlib' komutunu çalıştırın")
    except Exception as e:
        print(f"❌ Hata: {e}")
