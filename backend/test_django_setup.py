"""
Quick Django Server Test Script
"""

import subprocess
import sys
import time
import requests

def test_django_startup():
    """Django sunucusunun başlatılabilirliğini test et"""
    
    print("🧪 Django Sunucu Başlatma Testi")
    print("=" * 50)
    
    # Check if Django commands work
    print("1️⃣ Django kurulumu kontrol ediliyor...")
    try:
        result = subprocess.run(
            [sys.executable, "manage.py", "check"],
            capture_output=True,
            text=True,
            cwd="D:/py/bp/backend"
        )
        
        if result.returncode == 0:
            print("✅ Django check passed!")
            print(f"Output: {result.stdout}")
        else:
            print("❌ Django check failed!")
            print(f"Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Django check error: {e}")
        return False
    
    # Try to start development server briefly
    print("\n2️⃣ API endpoint'leri kontrol ediliyor...")
    try:
        # Try to import the URLs to check for syntax errors
        import os
        import django
        
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
        django.setup()
        
        from django.urls import reverse
        from django.test import Client
        
        client = Client()
        
        # Test API root
        try:
            response = client.get('/api/')
            print(f"✅ API root accessible: {response.status_code}")
        except Exception as e:
            print(f"⚠️ API root error: {e}")
        
        # Test accounts API endpoints
        social_endpoints = [
            '/api/accounts/auth/social/google/',
            '/api/accounts/auth/social/facebook/',
            '/api/accounts/auth/social/apple/',
            '/api/accounts/auth/login/',
            '/api/accounts/auth/register/',
        ]
        
        for endpoint in social_endpoints:
            try:
                response = client.post(endpoint, {}, content_type='application/json')
                print(f"✅ {endpoint}: {response.status_code}")
            except Exception as e:
                print(f"❌ {endpoint}: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Django test error: {e}")
        return False


def test_rate_limiting_import():
    """Rate limiting import'larını test et"""
    print("\n3️⃣ Rate limiting import'ları kontrol ediliyor...")
    
    try:
        from django_ratelimit.decorators import ratelimit
        from django.utils.decorators import method_decorator
        print("✅ Rate limiting imports successful!")
        return True
    except ImportError as e:
        print(f"❌ Rate limiting import error: {e}")
        print("   Install with: pip install django-ratelimit")
        return False


def test_serializers():
    """Serializers import'larını test et"""
    print("\n4️⃣ Serializers import'ları kontrol ediliyor...")
    
    try:
        import os
        import django
        
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
        django.setup()
        
        from accounts.api.serializers import (
            GoogleSocialLoginSerializer,
            FacebookSocialLoginSerializer,
            AppleSocialLoginSerializer,
            CustomTokenObtainPairSerializer
        )
        print("✅ Social login serializers import successful!")
        
        # Test serializer instantiation
        google_serializer = GoogleSocialLoginSerializer(data={'access_token': 'test'})
        print("✅ Google serializer instantiation successful!")
        
        return True
        
    except Exception as e:
        print(f"❌ Serializers import error: {e}")
        return False


def run_django_server_test():
    """Run a quick server test"""
    print("\n5️⃣ Django server quick test...")
    
    try:
        # Start server in background for a few seconds
        print("   Starting Django server on port 8001...")
        server_process = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", "8001"],
            cwd="D:/py/bp/backend",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait a moment for server to start
        time.sleep(3)
        
        # Test if server is responding
        try:
            response = requests.get("http://localhost:8001/api/", timeout=5)
            print(f"✅ Server responding: {response.status_code}")
            server_running = True
        except requests.RequestException as e:
            print(f"⚠️ Server not responding: {e}")
            server_running = False
        
        # Kill the server
        server_process.terminate()
        server_process.wait(timeout=5)
        
        return server_running
        
    except Exception as e:
        print(f"❌ Server test error: {e}")
        return False


def main():
    """Ana test fonksiyonu"""
    print("🚀 Django Social Login API Test Suite")
    print("=" * 60)
    
    tests = [
        ("Django Check", test_django_startup),
        ("Rate Limiting", test_rate_limiting_import),
        ("Serializers", test_serializers),
        ("Server Test", run_django_server_test),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Test Results Summary:")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print(f"\n📊 Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("\n🎉 All tests passed! Your Django social login API is ready!")
        print("\n🚀 Next steps:")
        print("   1. Run: python manage.py runserver")
        print("   2. Test social login endpoints")
        print("   3. Test rate limiting with: python test_rate_limiting.py")
    else:
        print("\n⚠️ Some tests failed. Please check the errors above.")
    
    return passed == len(tests)


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
