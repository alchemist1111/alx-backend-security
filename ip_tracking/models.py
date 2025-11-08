from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)

    # Geolocation fields
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    geolocation_data = models.JSONField(blank=True, null=True)  # Store full response
    
    class Meta:
        db_table = 'request_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
    
    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown"
        return f"{self.ip_address} - {location} - {self.path}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'blocked_ips'
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
    
    def __str__(self):
        return f"{self.ip_address} - {self.created_at}"


class SuspiciousIP(models.Model):
    REASON_CHOICES = [
        ('high_volume', 'High request volume'),
        ('sensitive_access', 'Access to sensitive paths'),
        ('multiple_sensitive', 'Multiple sensitive path accesses'),
        ('suspicious_pattern', 'Suspicious behavior pattern'),
    ]
    
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    description = models.TextField()
    request_count = models.IntegerField(default=0)
    detected_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'suspicious_ips'
        verbose_name = 'Suspicious IP'
        verbose_name_plural = 'Suspicious IPs'
        indexes = [
            models.Index(fields=['ip_address', 'detected_at']),
            models.Index(fields=['is_resolved']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()} - {self.detected_at}"
    
    def mark_resolved(self):
        self.is_resolved = True
        from django.utils import timezone
        self.resolved_at = timezone.now()
        self.save()