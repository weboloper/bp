"""
Custom decorators for common functionality
"""
import functools
import logging
from typing import Callable, Any
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit

logger = logging.getLogger(__name__)


def handle_errors(error_message: str = "Bir hata oluştu"):
    """Decorator to handle exceptions gracefully"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {str(e)}")
                if hasattr(args[0], 'META'):  # Django request object
                    return JsonResponse({
                        'success': False,
                        'error': error_message
                    }, status=500)
                raise
        return wrapper
    return decorator


def cache_result(timeout: int = 300, key_prefix: str = ''):
    """Cache function results"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, timeout)
            return result
        return wrapper
    return decorator


def ajax_required(func: Callable) -> Callable:
    """Decorator to ensure request is AJAX"""
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        if not request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            return JsonResponse({
                'success': False,
                'error': 'Bu endpoint sadece AJAX istekleri kabul eder'
            }, status=400)
        return func(request, *args, **kwargs)
    return wrapper


def api_key_required(func: Callable) -> Callable:
    """Simple API key authentication decorator"""
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        api_key = request.META.get('HTTP_X_API_KEY') or request.GET.get('api_key')
        if not api_key:
            return JsonResponse({
                'success': False,
                'error': 'API key gerekli'
            }, status=401)
        
        # Here you would validate the API key
        # For now, just check if it exists
        # In real implementation, check against database
        
        return func(request, *args, **kwargs)
    return wrapper


def log_execution(log_level: int = logging.INFO):
    """Log function execution with timing"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import time
            start_time = time.time()
            
            logger.log(log_level, f"Starting execution of {func.__name__}")
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.log(log_level, f"Completed {func.__name__} in {execution_time:.2f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"Error in {func.__name__} after {execution_time:.2f}s: {str(e)}")
                raise
        return wrapper
    return decorator


def staff_required(func: Callable) -> Callable:
    """Decorator to require staff status"""
    @functools.wraps(func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff:
            return JsonResponse({
                'success': False,
                'error': 'Bu işlem için staff yetkisi gerekli'
            }, status=403)
        return func(request, *args, **kwargs)
    return wrapper


# Rate limiting decorators
def rate_limit_api(group: str = 'api', rate: str = '100/h'):
    """Rate limit decorator for API endpoints"""
    def decorator(func: Callable) -> Callable:
        @ratelimit(group=group, key='ip', rate=rate, method='ALL')
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            if getattr(request, 'limited', False):
                return JsonResponse({
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.'
                }, status=429)
            return func(request, *args, **kwargs)
        return wrapper
    return decorator