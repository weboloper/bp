"""
Rate Limiting Test Script for Social Login APIs
"""

import requests
import time
import json


def test_rate_limiting():
    """
    Rate limiting özelliklerini test et
    """
    print("=== Rate Limiting Test ===\n")
    
    base_url = "http://localhost:8000/api/accounts"
    
    # Test scenarios
    test_scenarios = [
        {
            'name': 'Google Social Login Rate Limit',
            'url': f'{base_url}/auth/social/google/',
            'data': {'access_token': 'test_token'},
            'limit': '10/m',
            'expected_requests': 10
        },
        {
            'name': 'Regular Login Rate Limit', 
            'url': f'{base_url}/auth/login/',
            'data': {'username': 'test', 'password': 'test'},
            'limit': '15/m',
            'expected_requests': 15
        },
        {
            'name': 'Registration Rate Limit',
            'url': f'{base_url}/auth/register/',
            'data': {
                'username': 'testuser',
                'email': 'test@example.com',
                'password1': 'testpass123',
                'password2': 'testpass123'
            },
            'limit': '5/m',
            'expected_requests': 5
        },
        {
            'name': 'Password Reset Rate Limit',
            'url': f'{base_url}/auth/password-reset/',
            'data': {'email': 'test@example.com'},
            'limit': '3/h',
            'expected_requests': 3
        }
    ]
    
    for scenario in test_scenarios:
        print(f"🔍 Testing: {scenario['name']}")
        print(f"   Limit: {scenario['limit']}")
        print(f"   Expected: {scenario['expected_requests']} requests allowed")
        
        success_count = 0
        rate_limited_count = 0
        
        # Test rate limiting
        for i in range(scenario['expected_requests'] + 5):
            try:
                response = requests.post(scenario['url'], json=scenario['data'])
                
                if response.status_code == 429:
                    rate_limited_count += 1
                    print(f"   Request {i+1}: RATE LIMITED (429)")
                    break
                else:
                    success_count += 1
                    print(f"   Request {i+1}: Status {response.status_code}")
                
                # Small delay between requests
                time.sleep(0.1)
                
            except Exception as e:
                print(f"   Request {i+1}: ERROR - {e}")
        
        print(f"   ✅ Successful requests: {success_count}")
        print(f"   ⚠️  Rate limited: {rate_limited_count}")
        print(f"   📊 Rate limiting {'WORKING' if rate_limited_count > 0 else 'NOT DETECTED'}")
        print()
        
        # Wait a bit between different tests
        time.sleep(2)


def test_rate_limit_headers():
    """
    Rate limit headers'ları test et
    """
    print("=== Rate Limit Headers Test ===\n")
    
    url = "http://localhost:8000/api/accounts/auth/social/google/"
    data = {'access_token': 'test_token'}
    
    try:
        response = requests.post(url, json=data)
        
        print("Response Headers:")
        rate_limit_headers = {
            k: v for k, v in response.headers.items() 
            if 'rate' in k.lower() or 'limit' in k.lower()
        }
        
        if rate_limit_headers:
            for header, value in rate_limit_headers.items():
                print(f"  {header}: {value}")
        else:
            print("  No rate limit headers found")
            print("  (Note: django-ratelimit may not expose headers by default)")
        
        print(f"\nResponse Status: {response.status_code}")
        
    except Exception as e:
        print(f"Error: {e}")


def test_different_rate_limit_keys():
    """
    Farklı rate limit key'lerini test et (IP, user, user_or_ip)
    """
    print("=== Different Rate Limit Keys Test ===\n")
    
    # Test IP-based rate limiting
    print("🌐 Testing IP-based rate limiting (Google Social Login):")
    google_url = "http://localhost:8000/api/accounts/auth/social/google/"
    for i in range(12):  # 10/m limit
        try:
            response = requests.post(google_url, json={'access_token': 'test'})
            print(f"  Request {i+1}: {response.status_code}")
            if response.status_code == 429:
                print("  ✅ IP-based rate limiting working!")
                break
        except Exception as e:
            print(f"  Error: {e}")
    
    print()


def show_rate_limit_configuration():
    """
    Mevcut rate limit konfigürasyonunu göster
    """
    print("=== Current Rate Limit Configuration ===\n")
    
    configurations = [
        {
            'endpoint': '/api/accounts/auth/register/',
            'limit': '5/m',
            'key': 'ip',
            'description': 'User registration'
        },
        {
            'endpoint': '/api/accounts/auth/login/',
            'limit': '15/m', 
            'key': 'ip',
            'description': 'User login'
        },
        {
            'endpoint': '/api/accounts/auth/social/google/',
            'limit': '10/m',
            'key': 'ip', 
            'description': 'Google social login'
        },
        {
            'endpoint': '/api/accounts/auth/social/facebook/',
            'limit': '10/m',
            'key': 'ip',
            'description': 'Facebook social login'
        },
        {
            'endpoint': '/api/accounts/auth/social/apple/',
            'limit': '10/m',
            'key': 'ip',
            'description': 'Apple social login'
        },
        {
            'endpoint': '/api/accounts/auth/password-reset/',
            'limit': '3/h',
            'key': 'ip',
            'description': 'Password reset request'
        },
        {
            'endpoint': '/api/accounts/auth/password-reset-confirm/',
            'limit': '10/h',
            'key': 'ip',
            'description': 'Password reset confirmation'
        },
        {
            'endpoint': '/api/accounts/auth/password-change/',
            'limit': '10/h',
            'key': 'user',
            'description': 'Password change (authenticated)'
        },
        {
            'endpoint': '/api/accounts/auth/username-change/',
            'limit': '5/h',
            'key': 'user_or_ip',
            'description': 'Username change (authenticated)'
        },
        {
            'endpoint': '/api/accounts/auth/email-change/',
            'limit': '3/h',
            'key': 'user',
            'description': 'Email change request (authenticated)'
        },
        {
            'endpoint': '/api/accounts/auth/email-verify-resend/',
            'limit': '5/h',
            'key': 'ip',
            'description': 'Email verification resend'
        },
        {
            'endpoint': '/api/accounts/me/ (PATCH)',
            'limit': '20/h',
            'key': 'user',
            'description': 'Profile update (authenticated)'
        }
    ]
    
    print("📋 Rate Limit Configuration:")
    print("-" * 80)
    print(f"{'Endpoint':<40} {'Limit':<10} {'Key':<12} {'Description'}")
    print("-" * 80)
    
    for config in configurations:
        print(f"{config['endpoint']:<40} {config['limit']:<10} {config['key']:<12} {config['description']}")
    
    print("\n📝 Key Types:")
    print("  ip          - Rate limit per IP address")
    print("  user        - Rate limit per authenticated user")
    print("  user_or_ip  - Rate limit per user if authenticated, otherwise per IP")
    
    print("\n⏰ Time Units:")
    print("  /m  - per minute")
    print("  /h  - per hour")
    print("  /d  - per day")


def check_django_ratelimit_status():
    """
    Django ratelimit kütüphanesinin durumunu kontrol et
    """
    print("=== Django RateLimit Status Check ===\n")
    
    try:
        import django_ratelimit
        print(f"✅ django-ratelimit installed: {django_ratelimit.__version__}")
    except ImportError:
        print("❌ django-ratelimit not installed")
        print("   Install with: pip install django-ratelimit")
        return False
    
    # Test basic endpoint
    try:
        response = requests.get("http://localhost:8000/api/")
        print(f"✅ Django server running: {response.status_code}")
    except Exception as e:
        print(f"❌ Django server not accessible: {e}")
        return False
    
    return True


if __name__ == "__main__":
    try:
        print("🔒 Django Social Login Rate Limiting Test")
        print("=" * 50)
        
        # Check prerequisites
        if not check_django_ratelimit_status():
            exit(1)
        
        print()
        show_rate_limit_configuration()
        print()
        
        # Test rate limiting
        user_input = input("Do you want to run rate limiting tests? (y/n): ").lower()
        if user_input == 'y':
            test_rate_limiting()
            test_rate_limit_headers()
            test_different_rate_limit_keys()
        else:
            print("Rate limiting tests skipped.")
        
        print("\n✅ Rate limiting configuration completed!")
        print("\n💡 Tips:")
        print("  - Rate limits are enforced per IP address for anonymous endpoints")
        print("  - Authenticated endpoints use user-based rate limiting")
        print("  - Social login endpoints have higher limits for better UX")
        print("  - Password reset has stricter limits for security")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
