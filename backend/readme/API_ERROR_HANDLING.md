# API Error Handling Guide

## 🎯 Error Format'ları

### 1. Validation Errors (400)
Form/serializer validation hatalarında field-based error'lar döner.

#### Register Validation Error:
```json
{
  "username": ["Bu kullanıcı adı zaten alınmış"],
  "email": ["Bu email adresi zaten kayıtlı"]
}
```

#### Login Validation Error:
```json
{
  "non_field_errors": ["Kullanıcı adı veya şifre hatalı"]
}
```

#### Password Reset Validation Error:
```json
{
  "email": ["Geçerli bir e-posta adresi girin"]
}
```

#### Password Confirm Validation Error:
```json
{
  "password1": ["Bu şifre çok yaygın"],
  "password2": ["Şifreler eşleşmiyor"]
}
```

### 2. System Errors (400/401/403/500)
Sistem seviyesi hatalar detail-based format kullanır.

#### Authentication Error (401):
```json
{
  "detail": "Given token not valid for any token type",
  "code": "token_not_valid"
}
```

#### Permission Error (403):
```json
{
  "detail": "Bu işlem için yetkiniz yok"
}
```

#### Invalid Link Error (400):
```json
{
  "detail": "Geçersiz sıfırlama linki"
}
```

#### Server Error (500):
```json
{
  "detail": "Kayıt sırasında bir hata oluştu"
}
```

## 🛠️ JavaScript Error Handler

```javascript
/**
 * Universal API Error Handler
 * Handles all types of API errors consistently
 */
const handleError = (error) => {
  // Check if it's an axios error with response
  if (!error.response) {
    console.error('Network Error:', error.message);
    showToast('Bağlantı hatası. Lütfen tekrar deneyin.', 'error');
    return;
  }

  const { status, data } = error.response;
  
  // Handle different error types
  switch (status) {
    case 400:
      handleValidationError(data);
      break;
      
    case 401:
      handleAuthError(data);
      break;
      
    case 403:
      handlePermissionError(data);
      break;
      
    case 500:
      handleServerError(data);
      break;
      
    default:
      handleGenericError(data, status);
  }
};

/**
 * Handle validation errors (400)
 * Field-based or system validation errors
 */
const handleValidationError = (data) => {
  // Check if it's a detail error (system validation)
  if (data.detail) {
    showToast(data.detail, 'error');
    return;
  }
  
  // Handle field validation errors
  let hasFieldErrors = false;
  
  Object.keys(data).forEach(field => {
    const messages = Array.isArray(data[field]) ? data[field] : [data[field]];
    
    if (field === 'non_field_errors') {
      // Show general validation error as toast
      showToast(messages[0], 'error');
    } else {
      // Highlight specific field errors
      highlightFieldError(field, messages[0]);
      hasFieldErrors = true;
    }
  });
  
  // If only field errors, show generic message
  if (hasFieldErrors && !data.non_field_errors) {
    showToast('Lütfen form hatalarını düzeltin', 'warning');
  }
};

/**
 * Handle authentication errors (401)
 * Token invalid, expired, etc.
 */
const handleAuthError = (data) => {
  const message = data.detail || 'Oturum süreniz dolmuş';
  
  showToast(message, 'error');
  
  // Clear stored tokens
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  
  // Redirect to login (adjust based on your routing)
  setTimeout(() => {
    window.location.href = '/login';
  }, 1500);
};

/**
 * Handle permission errors (403)
 * User doesn't have required permissions
 */
const handlePermissionError = (data) => {
  const message = data.detail || 'Bu işlem için yetkiniz yok';
  
  showToast(message, 'error');
  
  // Optionally redirect or show permission dialog
  // showPermissionDialog();
};

/**
 * Handle server errors (500)
 * Internal server errors
 */
const handleServerError = (data) => {
  const message = data.detail || 'Sunucu hatası oluştu';
  
  showToast(message, 'error');
  
  // Log error for debugging
  console.error('Server Error:', data);
  
  // Optionally report to error tracking service
  // reportError('server_error', data);
};

/**
 * Handle other HTTP errors
 * Fallback for unexpected status codes
 */
const handleGenericError = (data, status) => {
  const message = data.detail || data.message || `HTTP ${status} hatası`;
  
  showToast(message, 'error');
  
  console.error(`HTTP ${status} Error:`, data);
};

/**
 * Helper: Show toast notification
 * Replace with your toast library (react-toastify, etc.)
 */
const showToast = (message, type = 'info') => {
  // Example with react-toastify
  // toast[type](message);
  
  // Example with custom toast
  // showNotification(message, type);
  
  // Fallback: console + alert
  console.log(`${type.toUpperCase()}: ${message}`);
  if (type === 'error') {
    alert(message);
  }
};

/**
 * Helper: Highlight field errors in form
 * Replace with your form validation library
 */
const highlightFieldError = (fieldName, message) => {
  // Example with vanilla JS
  const field = document.querySelector(`[name="${fieldName}"]`);
  if (field) {
    field.classList.add('error');
    
    // Show error message near field
    const errorEl = field.parentNode.querySelector('.error-message');
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }
  }
  
  // Example with React Hook Form
  // setError(fieldName, { message });
  
  // Example with Formik
  // setFieldError(fieldName, message);
};

/**
 * Helper: Clear field errors
 * Call this before making new API requests
 */
const clearFieldErrors = () => {
  document.querySelectorAll('.error').forEach(el => {
    el.classList.remove('error');
  });
  
  document.querySelectorAll('.error-message').forEach(el => {
    el.style.display = 'none';
  });
};

// Export for use in your app
export { 
  handleError, 
  showToast, 
  highlightFieldError, 
  clearFieldErrors 
};
```

## 📖 Usage Examples

### Register Form:
```javascript
const handleRegister = async (formData) => {
  try {
    clearFieldErrors();
    
    const response = await api.post('/api/accounts/auth/register/', formData);
    
    showToast('Kayıt başarılı! Email adresinizi kontrol edin.', 'success');
    // Redirect to email verification page
    
  } catch (error) {
    handleError(error);
  }
};
```

### Login Form:
```javascript
const handleLogin = async (credentials) => {
  try {
    clearFieldErrors();
    
    const response = await api.post('/api/accounts/auth/login/', credentials);
    
    // Store tokens
    localStorage.setItem('access_token', response.data.access);
    localStorage.setItem('refresh_token', response.data.refresh);
    
    showToast('Giriş başarılı!', 'success');
    // Redirect to dashboard
    
  } catch (error) {
    handleError(error);
  }
};
```

### Protected API Call:
```javascript
const fetchUserProfile = async () => {
  try {
    const response = await api.get('/api/accounts/me/', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('access_token')}`
      }
    });
    
    return response.data;
    
  } catch (error) {
    handleError(error);
    return null;
  }
};
```

### Password Reset:
```javascript
const handlePasswordReset = async (email) => {
  try {
    clearFieldErrors();
    
    await api.post('/api/accounts/auth/password-reset/', { email });
    
    showToast('Şifre sıfırlama linki email adresinize gönderildi.', 'success');
    
  } catch (error) {
    handleError(error);
  }
};
```

## 🎨 CSS for Field Errors

```css
/* Field error styling */
.error {
  border-color: #ef4444 !important;
  box-shadow: 0 0 0 1px #ef4444;
}

.error-message {
  color: #ef4444;
  font-size: 0.875rem;
  margin-top: 0.25rem;
  display: none;
}

.error-message.show {
  display: block;
}

/* Toast notification styling (if using custom toast) */
.toast {
  position: fixed;
  top: 20px;
  right: 20px;
  padding: 12px 20px;
  border-radius: 6px;
  color: white;
  font-weight: 500;
  z-index: 1000;
  animation: slideIn 0.3s ease-out;
}

.toast.success {
  background-color: #10b981;
}

.toast.error {
  background-color: #ef4444;
}

.toast.warning {
  background-color: #f59e0b;
}

@keyframes slideIn {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}
```

## 🔧 Framework-Specific Adaptations

### React + React Hook Form:
```javascript
import { useForm } from 'react-hook-form';

const MyForm = () => {
  const { setError, clearErrors } = useForm();
  
  const customHighlightFieldError = (fieldName, message) => {
    setError(fieldName, { message });
  };
  
  const customClearFieldErrors = () => {
    clearErrors();
  };
  
  // Use in handleError...
};
```

### Vue + VeeValidate:
```javascript
import { useForm } from 'vee-validate';

const { setFieldError, resetForm } = useForm();

const customHighlightFieldError = (fieldName, message) => {
  setFieldError(fieldName, message);
};

const customClearFieldErrors = () => {
  resetForm();
};
```

Bu error handler tüm API endpoint'leriniz için universal olarak kullanılabilir!
