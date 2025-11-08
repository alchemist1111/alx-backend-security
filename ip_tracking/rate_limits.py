from django_ratelimit.decorators import ratelimit
from functools import wraps

def rate_limit_authenticated(rate='10/m'):
    """Custom decorator for authenticated users"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Apply different rates based on authentication
            if request.user.is_authenticated:
                # Higher limit for authenticated users
                return ratelimit(key='user', rate=rate, method='ALL', block=True)(view_func)(request, *args, **kwargs)
            else:
                # Lower limit for anonymous users
                return ratelimit(key='ip', rate='5/m', method='ALL', block=True)(view_func)(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def rate_limit_by_group(group, rate):
    """Rate limit by custom groups"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            return ratelimit(key='ip', rate=rate, method='ALL', block=True, group=group)(view_func)(request, *args, **kwargs)
        return _wrapped_view
    return decorator



def get_client_ip(request):
    """Get client IP address for rate limiting"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def user_or_ip_key(request):
    """Rate limit key that uses user ID if authenticated, otherwise IP"""
    if request.user.is_authenticated:
        return f"user_{request.user.id}"
    return get_client_ip(request)