from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    path = models.CharField(max_length=200)

    def __str__(self):
        return f"Request from {self.ip_address} at {self.timestamp} for {self.path}"
