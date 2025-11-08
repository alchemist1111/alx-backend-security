from celery import shared_task
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def flag_suspicious_ips():
    """
    Flags IPs that:
    1. Made more than 100 requests in the last hour
    2. Accessed sensitive paths
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Query recent logs
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    # Count requests per IP
    ip_counts = {}
    for log in recent_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    # Flag IPs exceeding threshold
    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f'{count} requests in the past hour', 'path': log.path}
            )

    # Flag IPs accessing sensitive paths
    sensitive_logs = recent_logs.filter(path__in=SENSITIVE_PATHS)
    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f'Accessed sensitive path {log.path}', 'path': log.path}
        )