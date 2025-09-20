"""
Django Social Login API - Final Setup Test
Bu script tüm kurulumu test eder ve eksikleri rapor eder
"""

import os
import sys
import subprocess

def test_django_check():
    """Django check komutunu çalıştır"""
    print("🔍 Django check çalıştırılıyor...")
    
    try:
        os.chdir("D:/py/bp/backend")
        
        result = subprocess.run(
            [sys.executable, "manage.py", "check"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("✅ Django check başarılı!")
            return True
        else:
            print("❌ Django check hatası:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Django check exception: {e}")
        return False


def test_imports():
    """Gerekli import'ları test et"""
    print("🔍 Import'lar test ediliyor...")
    
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
        
        import django
        django.setup()
        
        # Test social login serializers
        from accounts.api.serializers import (
            GoogleSocialLoginSerializer,
            FacebookSocialLoginSerializer,
            AppleSocialLoginSerializer,
            CustomTokenObtainPairSerializer
        )
        print("✅ Social login serializers import başarılı!")
        
        # Test views
        from accounts.api.views import (
            GoogleSocialLoginAPIView,
            FacebookSocialLoginAPIView,
            AppleSocialLoginAPIView
        )
        print("✅ Social login views import başarılı!")
        
        # Test rate limiting
        from django_ratelimit.decorators import ratelimit
        print("✅ Rate limiting import başarılı!")
        
        return True
        
    except Exception as e:
        print(f"❌ Import hatası: {e}")
        return False


def test_urls():
    """URL patterns'ı test et"""
    print("🔍 URL patterns test ediliyor...")
    
    try:
        from django.test import Client
        from django.urls import reverse
        
        client = Client()
        
        # Test some endpoints
        test_urls = [
            '/api/',
            '/api/accounts/auth/social/google/',
            '/api/accounts/auth/social/facebook/',
            '/api/accounts/auth/social/apple/',
            '/api/accounts/auth/login/',
            '/api/accounts/auth/register/',
        ]
        
        for url in test_urls:
            try:
                response = client.get(url)
                print(f"✅ {url}: {response.status_code}")
            except Exception as e:
                print(f"❌ {url}: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ URL test hatası: {e}")
        return False


def print_summary():
    """Kurulum özeti ve sonraki adımlar"""
    print("\n" + "="*60)
    print("🎉 Django Social Login API Kurulumu Tamamlandı!")
    print("="*60)
    
    print("\n🚀 Artık Kullanabilecekleriniz:")
    print("   ✅ Google Social Login API")
    print("   ✅ Facebook Social Login API") 
    print("   ✅ Apple Social Login API")
    print("   ✅ Rate Limiting (10 req/min for social login)")
    print("   ✅ JWT Token Authentication")
    print("   ✅ Custom Username/Email Login")
    
    print("\n📋 API Endpoints:")
    print("   POST /api/accounts/auth/social/google/")
    print("   POST /api/accounts/auth/social/facebook/")
    print("   POST /api/accounts/auth/social/apple/")
    print("   POST /api/accounts/auth/login/")
    print("   POST /api/accounts/auth/register/")
    
    print("\n🔧 Sunucuyu Başlatma:")
    print("   cd backend")
    print("   python manage.py runserver")
    
    print("\n🧪 Test Etme:")
    print("   python test_rate_limiting.py")
    print("   python test_django_setup.py")
    
    print("\n📚 Dokümantasyon:")
    print("   RATE_LIMITING_GUIDE.md - Rate limiting rehberi")
    print("   API_USAGE_EXAMPLES.md - API kullanım örnekleri")
    
    print("\n🔑 Örnek API Kullanımı:")
    print("   # Google Login")
    print("   curl -X POST http://localhost:8000/api/accounts/auth/social/google/ \\")
    print("     -H 'Content-Type: application/json' \\")
    print("     -d '{\"access_token\": \"YOUR_GOOGLE_ACCESS_TOKEN\"}'")
    
    print("\n💡 İpuçları:")
    print("   - Social login için frontend'den alınan access token'ları kullanın")
    print("   - Rate limiting IP bazlı çalışır")
    print("   - Tüm social login kullanıcıları otomatik verified olur")
    print("   - JWT token'lar 1 saat geçerlidir")


def main():
    """Ana test fonksiyonu"""
    print("🔥 Django Social Login API - Final Setup Test")
    print("="*60)
    
    tests = [
        ("Django Check", test_django_check),
        ("Imports", test_imports),
        ("URLs", test_urls),
    ]
    
    all_passed = True
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name} Test:")
        result = test_func()
        if not result:
            all_passed = False
            print(f"❌ {test_name} failed!")
    
    print("\n" + "="*60)
    if all_passed:
        print("🎊 TÜM TESTLER BAŞARILI!")
        print_summary()
    else:
        print("⚠️ Bazı testler başarısız oldu. Lütfen hataları kontrol edin.")
    
    return all_passed


if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🚀 Django sunucusunu başlatmak için:")
            print("   cd backend && python manage.py runserver")
    except KeyboardInterrupt:
        print("\n\n⚠️ Test kullanıcı tarafından iptal edildi")
    except Exception as e:
        print(f"\n❌ Beklenmeyen hata: {e}")
