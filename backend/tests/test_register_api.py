"""
Register API endpoint test scripti
"""

import requests
import json
import string
import random


def generate_test_data():
    """
    Test için random user data oluştur
    """
    random_suffix = ''.join(random.choices(string.digits, k=4))
    
    return {
        'username': f'testuser{random_suffix}',
        'email': f'test{random_suffix}@example.com',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!'
    }


def test_register_api():
    """
    Register API endpoint'ini test et
    """
    print("=== Register API Test ===\n")
    
    base_url = "http://localhost:8000/api/accounts"
    register_url = f"{base_url}/auth/register/"
    
    # 1. Geçersiz verilerle testler
    print("🧪 Geçersiz Veri Testleri:")
    
    invalid_cases = [
        {
            'name': 'Boş username',
            'data': {'username': '', 'email': 'test@example.com', 'password1': 'pass123', 'password2': 'pass123'}
        },
        {
            'name': 'Geçersiz email format',
            'data': {'username': 'testuser', 'email': 'invalid-email', 'password1': 'pass123', 'password2': 'pass123'}
        },
        {
            'name': 'Şifreler eşleşmiyor',
            'data': {'username': 'testuser', 'email': 'test@example.com', 'password1': 'pass123', 'password2': 'different'}
        },
        {
            'name': 'Çok kısa username',
            'data': {'username': 'ab', 'email': 'test@example.com', 'password1': 'TestPass123!', 'password2': 'TestPass123!'}
        },
        {
            'name': 'Zayıf şifre',
            'data': {'username': 'testuser', 'email': 'test@example.com', 'password1': '123', 'password2': '123'}
        }
    ]\n    \n    for i, test_case in enumerate(invalid_cases, 1):\n        print(f\"\\n{i}. {test_case['name']}:\")\n        \n        response = requests.post(register_url, json=test_case['data'])\n        \n        print(f\"   Status: {response.status_code}\")\n        \n        if response.status_code == 400:\n            try:\n                error_data = response.json()\n                if 'errors' in error_data:\n                    print(f\"   Validation Errors: {json.dumps(error_data['errors'], ensure_ascii=False)}\")\n                else:\n                    print(f\"   Error: {json.dumps(error_data, ensure_ascii=False)}\")\n            except:\n                print(f\"   Response: {response.text}\")\n        else:\n            print(f\"   Unexpected status: {response.status_code}\")\n    \n    print(\"\\n\" + \"=\"*50)\n    \n    # 2. Başarılı kayıt testi\n    print(\"\\n✅ Başarılı Kayıt Testi:\")\n    \n    # Random test data oluştur\n    test_data = generate_test_data()\n    print(f\"Test Data: {json.dumps({k: v for k, v in test_data.items() if 'password' not in k}, indent=2)}\")\n    \n    # Register request\n    response = requests.post(register_url, json=test_data)\n    \n    print(f\"\\nStatus: {response.status_code}\")\n    \n    if response.status_code == 201:\n        success_data = response.json()\n        print(\"🎉 Kayıt başarılı!\")\n        print(f\"Response: {json.dumps(success_data, indent=2, ensure_ascii=False)}\")\n        \n        # 3. Login test ile doğrula\n        print(\"\\n🔐 Login Test (Email doğrulanmamış):\")\n        login_url = f\"{base_url}/auth/login/\"\n        \n        login_response = requests.post(login_url, json={\n            'username': test_data['username'],\n            'password': test_data['password1']\n        })\n        \n        print(f\"Login Status: {login_response.status_code}\")\n        \n        if login_response.status_code == 400:\n            login_error = login_response.json()\n            print(f\"Expected Error: {json.dumps(login_error, ensure_ascii=False)}\")\n            print(\"✅ Doğrulanmamış hesap login'i engellendi (doğru davranış)\")\n        else:\n            print(f\"Unexpected login result: {login_response.json()}\")\n        \n        # 4. Aynı verilerle tekrar kayıt dene (duplicate test)\n        print(\"\\n🔁 Duplicate Registration Test:\")\n        duplicate_response = requests.post(register_url, json=test_data)\n        \n        print(f\"Status: {duplicate_response.status_code}\")\n        if duplicate_response.status_code == 400:\n            duplicate_error = duplicate_response.json()\n            print(f\"Expected Error: {json.dumps(duplicate_error, ensure_ascii=False)}\")\n            print(\"✅ Duplicate kayıt engellendi (doğru davranış)\")\n    else:\n        print(f\"❌ Kayıt başarısız: {response.status_code}\")\n        try:\n            error_data = response.json()\n            print(f\"Error: {json.dumps(error_data, indent=2, ensure_ascii=False)}\")\n        except:\n            print(f\"Response: {response.text}\")\n\n\ndef show_register_info():\n    \"\"\"\n    Register endpoint bilgilerini göster\n    \"\"\"\n    print(\"🎯 Register API Endpoint:\")\n    print(\"  📍 POST /api/accounts/auth/register/\")\n    \n    print(\"\\n📋 Request Format:\")\n    print(\"\"\"\n{\n  \"username\": \"testuser\",\n  \"email\": \"test@example.com\",\n  \"password1\": \"SecurePass123!\",\n  \"password2\": \"SecurePass123!\"\n}\n    \"\"\")\n    \n    print(\"📤 Success Response (201):\")\n    print(\"\"\"\n{\n  \"message\": \"Kayıt başarılı! Email adresinize doğrulama linki gönderildi.\",\n  \"user\": {\n    \"id\": 1,\n    \"username\": \"testuser\",\n    \"email\": \"test@example.com\"\n  },\n  \"email_sent\": true\n}\n    \"\"\")\n    \n    print(\"❌ Error Response (400):\")\n    print(\"\"\"\n{\n  \"error\": \"Validation failed\",\n  \"errors\": {\n    \"username\": [\"Bu kullanıcı adı zaten alınmış\"],\n    \"email\": [\"Bu email adresi zaten kayıtlı\"],\n    \"password2\": [\"Şifreler eşleşmiyor\"]\n  }\n}\n    \"\"\")\n    \n    print(\"🔒 Validation Rules:\")\n    print(\"  • Username: 3-30 karakter, alphanumeric\")\n    print(\"  • Email: Geçerli format, unique\")\n    print(\"  • Password: Django's password validation\")\n    print(\"  • Password confirmation must match\")\n    \n    print(\"\\n📧 Email Flow:\")\n    print(\"  1. Register → User created (is_verified=False)\")\n    print(\"  2. Email verification link sent\")\n    print(\"  3. User clicks link → is_verified=True\")\n    print(\"  4. User can login\")\n    \n    print(\"\\n🌐 Frontend Usage:\")\n    print(\"\"\"\n// Register\nconst response = await fetch('/api/accounts/auth/register/', {\n  method: 'POST',\n  headers: { 'Content-Type': 'application/json' },\n  body: JSON.stringify({\n    username: 'newuser',\n    email: 'user@example.com',\n    password1: 'SecurePass123!',\n    password2: 'SecurePass123!'\n  })\n});\n\nif (response.status === 201) {\n  const data = await response.json();\n  // Show success message, redirect to email verification page\n} else {\n  const errors = await response.json();\n  // Show validation errors\n}\n    \"\"\")\n\n\nif __name__ == \"__main__\":\n    try:\n        show_register_info()\n        \n        print(\"\\n\" + \"=\"*50)\n        print(\"🌐 Django sunucusu kontrolü...\")\n        \n        response = requests.get(\"http://localhost:8000/api/\")\n        print(f\"API Root Status: {response.status_code}\")\n        \n        if response.status_code == 200:\n            test_register_api()\n        else:\n            print(\"❌ API erişilemiyor. Django sunucusunu başlattınız mı?\")\n            \n    except requests.exceptions.ConnectionError:\n        print(\"❌ Django sunucusu çalışmıyor!\")\n        print(\"Önce 'python manage.py runserver' komutunu çalıştırın\")\n    except Exception as e:\n        print(f\"❌ Hata: {e}\")\n