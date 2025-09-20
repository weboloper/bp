# Rate Limiting Configuration & Monitoring Guide

## 🔒 Rate Limiting Implemented!

Your Django social login API now has comprehensive rate limiting protection using `django-ratelimit`.

### 📊 Current Rate Limits

| Endpoint | Limit | Key Type | Description |
|----------|--------|----------|-------------|
| **Social Login** |
| `/api/accounts/auth/social/google/` | 10/minute | IP | Google OAuth login |
| `/api/accounts/auth/social/facebook/` | 10/minute | IP | Facebook OAuth login |
| `/api/accounts/auth/social/apple/` | 10/minute | IP | Apple OAuth login |
| **Authentication** |
| `/api/accounts/auth/login/` | 15/minute | IP | Regular login |
| `/api/accounts/auth/register/` | 5/minute | IP | User registration |
| **Password Management** |
| `/api/accounts/auth/password-reset/` | 3/hour | IP | Password reset request |
| `/api/accounts/auth/password-reset-confirm/` | 10/hour | IP | Password reset confirm |
| `/api/accounts/auth/password-change/` | 10/hour | User | Password change |
| **Account Management** |
| `/api/accounts/auth/username-change/` | 5/hour | User or IP | Username change |
| `/api/accounts/auth/email-change/` | 3/hour | User | Email change request |
| `/api/accounts/auth/email-verify-resend/` | 5/hour | IP | Email verification resend |
| `/api/accounts/me/` (PATCH) | 20/hour | User | Profile updates |

### 🔑 Key Types Explained

- **IP**: Rate limit per IP address (for anonymous users)
- **User**: Rate limit per authenticated user
- **User or IP**: Rate limit per user if authenticated, otherwise per IP

### 🚀 How to Test Rate Limiting

```bash
# Run the rate limiting test
cd backend
python test_rate_limiting.py

# Test specific endpoint manually
curl -X POST http://localhost:8000/api/accounts/auth/social/google/ \
  -H "Content-Type: application/json" \
  -d '{"access_token": "test"}' \
  -v
```

### 📈 Monitoring Rate Limits

#### View Rate Limit Violations (Django Shell)
```python
python manage.py shell

# Check recent rate limit violations
from django.core.cache import cache
from django.conf import settings

# List all cache keys (if using Redis)
if hasattr(cache, '_cache') and hasattr(cache._cache, 'keys'):
    rate_limit_keys = [k for k in cache._cache.keys() if 'rl:' in k]
    print("Active rate limit keys:", rate_limit_keys)
```

#### Create Rate Limit Monitoring Model
```python
# Add to accounts/models.py
class RateLimitViolation(models.Model):
    ip_address = models.GenericIPAddressField()
    endpoint = models.CharField(max_length=200)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['endpoint', 'timestamp']),
        ]
```

### 🛠️ Customizing Rate Limits

#### Adjust Limits in views.py
```python
# Change rate limit for Google login
@method_decorator(ratelimit(key='ip', rate='20/m', method='POST'), name='post')
class GoogleSocialLoginAPIView(APIView):
    # ...

# Use different keys
@method_decorator(ratelimit(key='user_or_ip', rate='100/h', method='POST'), name='post')
class SomeAPIView(APIView):
    # ...

# Multiple decorators for different limits
@method_decorator([
    ratelimit(key='ip', rate='10/m', method='POST'),
    ratelimit(key='user', rate='100/h', method='POST'),
], name='post')
class AdvancedAPIView(APIView):
    # ...
```

#### Environment-Based Configuration
```python
# settings.py
SOCIAL_LOGIN_RATE_LIMIT = env('SOCIAL_LOGIN_RATE_LIMIT', default='10/m')
LOGIN_RATE_LIMIT = env('LOGIN_RATE_LIMIT', default='15/m')

# Then in views.py
from django.conf import settings

@method_decorator(ratelimit(key='ip', rate=settings.SOCIAL_LOGIN_RATE_LIMIT, method='POST'), name='post')
class GoogleSocialLoginAPIView(APIView):
    # ...
```

### 🔧 Advanced Configuration

#### Custom Rate Limit Response
```python
# Create custom rate limit handler
def rate_limit_handler(request, exception):
    return JsonResponse({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': 60  # seconds
    }, status=429)

# Add to settings.py
RATELIMIT_VIEW = 'accounts.api.views.rate_limit_handler'
```

#### Rate Limit Middleware
```python
# Create middleware/rate_limit.py
class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Log rate limit violations
        if hasattr(request, 'limited') and request.limited:
            # Log to database or monitoring service
            pass
            
        return response

# Add to MIDDLEWARE in settings.py
MIDDLEWARE = [
    # ... other middleware
    'middleware.rate_limit.RateLimitMiddleware',
]
```

### 📊 Production Monitoring

#### Grafana Dashboard Queries (if using Redis)
```redis
# Rate limit violations count
INFO keyspace
KEYS rl:*

# Monitor rate limit key expiry
TTL rl:ip:192.168.1.1:accounts.api.views.GoogleSocialLoginAPIView
```

#### CloudWatch/DataDog Metrics
```python
# Add to views.py
import boto3
import logging

rate_limit_logger = logging.getLogger('rate_limits')

def post(self, request):
    try:
        # Your existing logic
        pass
    except Exception as e:
        if hasattr(request, 'limited') and request.limited:
            # Send to CloudWatch
            cloudwatch = boto3.client('cloudwatch')
            cloudwatch.put_metric_data(
                Namespace='Django/RateLimit',
                MetricData=[{
                    'MetricName': 'RateLimitViolations',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'Endpoint', 'Value': 'GoogleSocialLogin'},
                        {'Name': 'IP', 'Value': request.META.get('REMOTE_ADDR')}
                    ]
                }]
            )
```

### 🚨 Security Best Practices

1. **Different Limits for Different Actions**
   - Login attempts: Moderate (15/min)
   - Registration: Conservative (5/min) 
   - Password reset: Very conservative (3/hour)
   - Social login: Liberal (10/min) for better UX

2. **IP-based vs User-based**
   - Anonymous endpoints: IP-based
   - Authenticated endpoints: User-based
   - Sensitive operations: Both IP and User limits

3. **Monitoring & Alerting**
   - Track rate limit violations
   - Alert on unusual patterns
   - Monitor for distributed attacks

### 🧪 Testing Rate Limits

```bash
# Test with Apache Bench
ab -n 100 -c 10 -H "Content-Type: application/json" \
   -p test_data.json \
   http://localhost:8000/api/accounts/auth/social/google/

# Test with curl loop
for i in {1..20}; do
  curl -X POST http://localhost:8000/api/accounts/auth/social/google/ \
    -H "Content-Type: application/json" \
    -d '{"access_token": "test"}' \
    -w "Request $i: %{http_code}\n" \
    -s -o /dev/null
  sleep 0.1
done
```

### 📝 Next Steps

1. **Monitor in Production**: Set up alerts for rate limit violations
2. **Adjust Limits**: Fine-tune based on real usage patterns  
3. **Advanced Features**: Consider implementing sliding windows or distributed rate limiting
4. **Documentation**: Update API documentation with rate limit information

Your social login system is now protected against abuse while maintaining good user experience! 🎉
