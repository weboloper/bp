"""
Google OAuth Login Test Script
Bu script Google OAuth ayarlarınızı test eder
"""

import os
import sys
import django

# Django setup
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.conf import settings

def test_google_oauth_settings():
    """Google OAuth ayarlarını test et"""
    print("\n" + "="*50)
    print("🔍 GOOGLE OAUTH SETTINGS TEST")
    print("="*50 + "\n")
    
    # 1. Client ID kontrolü
    client_id = settings.GOOGLE_OAUTH2_CLIENT_ID
    if client_id and len(client_id) > 10:
        print("✅ Google Client ID: Tanımlı")
        print(f"   ID: {client_id[:20]}...{client_id[-10:]}")
    else:
        print("❌ Google Client ID: TANIMLI DEĞİL!")
        print("   .env dosyanıza GOOGLE_OAUTH2_CLIENT_ID ekleyin")
        return False
    
    # 2. Client Secret kontrolü
    client_secret = settings.GOOGLE_OAUTH2_CLIENT_SECRET
    if client_secret and len(client_secret) > 10:
        print("✅ Google Client Secret: Tanımlı")
        print(f"   Secret: {client_secret[:10]}...{'*' * 10}")
    else:
        print("❌ Google Client Secret: TANIMLI DEĞİL!")
        print("   .env dosyanıza GOOGLE_OAUTH2_CLIENT_SECRET ekleyin")
        return False
    
    # 3. Frontend URL kontrolü
    frontend_url = settings.FRONTEND_URL
    print(f"\n✅ Frontend URL: {frontend_url}")
    
    # 4. Debug mode kontrolü
    debug = settings.DEBUG
    print(f"✅ Debug Mode: {debug}")
    
    # 5. Allowed hosts kontrolü
    allowed_hosts = settings.ALLOWED_HOSTS
    print(f"✅ Allowed Hosts: {allowed_hosts}")
    
    # 6. URL'leri göster
    print("\n" + "-"*50)
    print("📋 GOOGLE OAUTH URLS")
    print("-"*50)
    
    if debug:
        base_url = "http://localhost:8000"
    else:
        base_url = f"https://{allowed_hosts[0] if allowed_hosts and allowed_hosts[0] != '*' else 'yourdomain.com'}"
    
    print(f"\n🔗 Login URL:")
    print(f"   {base_url}/accounts/login/")
    
    print(f"\n🔗 Google Login URL:")
    print(f"   {base_url}/accounts/google-login/")
    
    print(f"\n🔗 Google Callback URL (Redirect URI):")
    print(f"   {base_url}/accounts/google-callback/")
    print(f"\n   ⚠️  Bu URL'i Google Cloud Console'da")
    print(f"      'Authorized redirect URIs' bölümüne ekleyin!")
    
    print("\n" + "-"*50)
    print("✅ SETUP CHECKLIST")
    print("-"*50)
    
    print("\n1. Google Cloud Console:")
    print("   ☐ Proje oluşturuldu")
    print("   ☐ OAuth 2.0 Client ID oluşturuldu")
    print("   ☐ Redirect URI eklendi:")
    print(f"      {base_url}/accounts/google-callback/")
    
    print("\n2. Environment Variables (.env):")
    print(f"   {'✅' if client_id else '☐'} GOOGLE_OAUTH2_CLIENT_ID")
    print(f"   {'✅' if client_secret else '☐'} GOOGLE_OAUTH2_CLIENT_SECRET")
    
    print("\n3. Dependencies:")
    try:
        import requests
        print("   ✅ requests library")
    except ImportError:
        print("   ❌ requests library - pip install requests")
        return False
    
    print("\n4. URL Configuration:")
    from django.urls import reverse
    try:
        google_login_url = reverse('accounts:google_login')
        print(f"   ✅ google_login URL: {google_login_url}")
        
        google_callback_url = reverse('accounts:google_callback')
        print(f"   ✅ google_callback URL: {google_callback_url}")
    except Exception as e:
        print(f"   ❌ URL configuration error: {e}")
        return False
    
    print("\n" + "="*50)
    print("🎉 GOOGLE OAUTH SETTINGS: BAŞARILI!")
    print("="*50)
    print("\n💡 Şimdi test etmek için:")
    print("   1. python manage.py runserver")
    print(f"   2. {base_url}/accounts/login/")
    print("   3. 'Google ile Giriş Yap' butonuna tıklayın")
    print("\n")
    
    return True

if __name__ == '__main__':
    try:
        success = test_google_oauth_settings()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
