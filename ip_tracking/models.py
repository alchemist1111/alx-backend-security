from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    path = models.CharField(max_length=200)

    def __str__(self):
        return f"Request from {self.ip_address} at {self.timestamp} for {self.path}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, help_text="IPv4 or IPv6 address")
    reason = models.CharField(max_length=255, null=True, blank=True)  # Add this field if needed
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address    
