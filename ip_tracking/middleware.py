from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
from .geolocation import GeolocationService

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geolocation_service = GeolocationService()
    
    def __call__(self, request):
        # Check if IP is blocked BEFORE processing the request
        if self.is_ip_blocked(request):
            return HttpResponseForbidden("IP address blocked")
        
        # Process the request and get the response
        response = self.get_response(request)
        
        # Log the request details after getting the response
        self.log_request(request)
        
        return response
    
    def is_ip_blocked(self, request):
        """Check if the client IP is in the blocked list"""
        try:
            ip_address = self.get_client_ip(request)
            return BlockedIP.objects.filter(ip_address=ip_address).exists()
        except Exception as e:
            # If there's an error checking, allow the request (fail open)
            print(f"Error checking IP block: {e}")
            return False
    

    def get_geolocation_data(self, ip_address):
        """Get geolocation data for IP with 24-hour caching"""
        cache_key = f"ip_geolocation_{ip_address}"

        # Try to get from cache first
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            # Get geolocation using django-ipgeolocation
            geolocator = Geolocation()
            geo_data = geolocator.get_geolocation(ip=ip_address)
            
            # Extract relevant fields
            processed_data = {
                'country': geo_data.get('country'),
                'country_code': geo_data.get('country_code'),
                'city': geo_data.get('city'),
                'region': geo_data.get('region'),
                'latitude': geo_data.get('latitude'),
                'longitude': geo_data.get('longitude'),
                'timezone': geo_data.get('timezone'),
                'isp': geo_data.get('isp'),
                'raw_data': geo_data  # Store complete response
            }
            
            # Cache for 24 hours (86400 seconds)
            cache.set(cache_key, processed_data, 86400)
            
            return processed_data
    
        except Exception as e:
            # Return empty data if geolocation fails
            print(f"Geolocation error for IP {ip_address}: {e}")
            return {
                'country': None,
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'error': str(e)
            }

    def log_request(self, request):
        """Extract and log IP address, timestamp, path, and geolocation"""
        try:
            # Get client IP address
            ip_address = self.get_client_ip(request)
            
            # Get geolocation data using our enhanced service
            geolocation_data = self.geolocation_service.get_geolocation(ip_address)
            
            # Create and save the log entry
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geolocation_data.get('country'),
                city=geolocation_data.get('city'),
                region=geolocation_data.get('region'),
                latitude=geolocation_data.get('latitude'),
                longitude=geolocation_data.get('longitude'),
                geolocation_data=geolocation_data
            )
        except Exception as e:
            # Log the error but don't break the application
            print(f"Error logging request: {e}")
    
    def get_client_ip(self, request):
        """Extract client IP address, handling proxy headers"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs, the first one is the client
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip