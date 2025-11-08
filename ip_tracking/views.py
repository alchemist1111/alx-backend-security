from django.http import JsonResponse
from .models import RequestLog
import json
from .rate_limits import rate_limit_authenticated, rate_limit_by_group
from .models import SuspiciousIP
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login

from ip_tracking import models


def home(request):
    return JsonResponse({
        'message': 'IP Tracking Project with Geolocation is working!',
        'total_logs': RequestLog.objects.count(),
        'your_ip': request.META.get('REMOTE_ADDR'),
        'user': str(request.user) if request.user.is_authenticated else 'Anonymous'
    })

def view_logs(request):
    logs = RequestLog.objects.all()[:10]  # Last 10 logs
    log_data = [
        {
            'ip': log.ip_address, 
            'path': log.path, 
            'timestamp': str(log.timestamp),
            'country': log.country,
            'city': log.city,
            'region': log.region,
            'location': f"{log.city}, {log.country}" if log.city and log.country else "Unknown"
        }
        for log in logs
    ]
    return JsonResponse({'recent_logs': log_data})

def geolocation_stats(request):
    """View to show geolocation statistics"""
    stats = {
        'total_requests': RequestLog.objects.count(),
        'countries': list(RequestLog.objects.exclude(country__isnull=True)
                          .values('country')
                          .distinct()
                          .count()),
        'cities': list(RequestLog.objects.exclude(city__isnull=True)
                       .values('city', 'country')
                       .distinct()),
        'requests_by_country': list(RequestLog.objects.exclude(country__isnull=True)
                                   .values('country')
                                   .annotate(count=models.Count('id'))
                                   .order_by('-count')[:10])
    }
    return JsonResponse(stats)



def rate_limit_exceeded(request, exception):
    """Custom view for when rate limit is exceeded"""
    return JsonResponse({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'status_code': 429
    }, status=429)

# Sensitive view with rate limiting for anonymous users
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
def login_view(request):
    """Login view with rate limiting"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return JsonResponse({
                    'message': 'Login successful',
                    'user': user.username,
                    'email': user.email
                })
            else:
                return JsonResponse({
                    'error': 'Invalid credentials'
                }, status=401)
        except json.JSONDecodeError:
            return JsonResponse({
                'error': 'Invalid JSON'
            }, status=400)
    
    return JsonResponse({
        'error': 'Method not allowed',
        'allowed_methods': ['POST']
    }, status=405)

# View with different rate limits for authenticated vs anonymous users
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
@csrf_exempt
def sensitive_operation(request):
    """A view that performs sensitive operations with rate limiting"""
    if request.method == 'POST':
        # Check if user is authenticated for different rate limits
        if request.user.is_authenticated:
            # Authenticated users get higher limits (handled by decorator)
            return JsonResponse({
                'message': 'Sensitive operation completed successfully',
                'user': request.user.username,
                'status': 'authenticated'
            })
        else:
            # Anonymous users get lower limits (handled by decorator)
            return JsonResponse({
                'message': 'Sensitive operation completed successfully',
                'status': 'anonymous'
            })
    
    return JsonResponse({
        'error': 'Method not allowed',
        'allowed_methods': ['POST']
    }, status=405)

# API endpoint with IP-based rate limiting
@ratelimit(key='ip', rate='10/m', method='GET', block=True)
def api_endpoint(request):
    """API endpoint with IP-based rate limiting"""
    return JsonResponse({
        'message': 'API response',
        'endpoint': 'api',
        'rate_limit': '10 requests per minute per IP'
    })

# View with method-specific rate limiting
@ratelimit(key='ip', rate='20/m', method='GET')
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@csrf_exempt
def multi_method_view(request):
    """View with different rate limits for different HTTP methods"""
    if request.method == 'GET':
        return JsonResponse({
            'message': 'GET request successful',
            'method': 'GET'
        })
    elif request.method == 'POST':
        return JsonResponse({
            'message': 'POST request successful',
            'method': 'POST'
        })
    
    return JsonResponse({
        'error': 'Method not allowed'
    }, status=405)



# View using custom authenticated rate limiting
@rate_limit_authenticated(rate='10/m')
@csrf_exempt
def authenticated_sensitive_view(request):
    """View with automatic rate limiting based on authentication"""
    if request.user.is_authenticated:
        return JsonResponse({
            'message': 'Authenticated access',
            'user': request.user.username,
            'rate_limit': '10 requests/minute'
        })
    else:
        return JsonResponse({
            'message': 'Anonymous access',
            'rate_limit': '5 requests/minute'
        })

# View with group-based rate limiting
@rate_limit_by_group('api', '100/h')
def high_limit_api(request):
    """API endpoint with higher rate limit"""
    return JsonResponse({
        'message': 'High limit API',
        'rate_limit': '100 requests per hour'
    })

@rate_limit_by_group('sensitive', '10/m')
def low_limit_sensitive(request):
    """Sensitive endpoint with lower rate limit"""
    return JsonResponse({
        'message': 'Sensitive endpoint',
        'rate_limit': '10 requests per minute'
    })


def suspicious_ips_view(request):
    """View to see currently suspicious IPs"""
    suspicious_ips = SuspiciousIP.objects.filter(is_resolved=False)
    
    ip_data = [
        {
            'ip_address': ip.ip_address,
            'reason': ip.reason,
            'reason_display': ip.get_reason_display(),
            'description': ip.description,
            'request_count': ip.request_count,
            'detected_at': str(ip.detected_at),
        }
        for ip in suspicious_ips
    ]
    
    return JsonResponse({
        'suspicious_ips': ip_data,
        'total_count': suspicious_ips.count()
    })