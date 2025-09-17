from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from .views import CustomTokenObtainPairView
# Cookie-based views (Farklı host için devre dışı)
# from .auth_views import (
#     login_cookie,
#     logout_cookie,
#     token_verify_cookie,
#     token_refresh_cookie
# )

app_name = 'accounts_api'

urlpatterns = [
    # Custom Django Simple JWT views - Username/Email destekli
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Cookie-based endpoints (Farklı host'ta çalışmaz - devre dışı)
    # path('auth/login-cookie/', login_cookie, name='login_cookie'),
    # path('auth/logout-cookie/', logout_cookie, name='logout_cookie'),
    # path('auth/token/verify-cookie/', token_verify_cookie, name='token_verify_cookie'),
    # path('auth/token/refresh-cookie/', token_refresh_cookie, name='token_refresh_cookie'),
]
