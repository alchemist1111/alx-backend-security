from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP
import ipaddress

class Command(BaseCommand):
    help = 'Add IP addresses to the blocklist'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP addresses to block (space separated)'
        )
        
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address(es)'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options.get('reason', 'No reason provided')
        
        blocked_count = 0
        skipped_count = 0
        
        for ip_str in ip_addresses:
            try:
                # Validate IP address
                ipaddress.ip_address(ip_str)
                
                # Create or get the blocked IP entry
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip_str,
                    defaults={'reason': reason}
                )
                
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f'Successfully blocked IP: {ip_str}')
                    )
                    blocked_count += 1
                else:
                    self.stdout.write(
                        self.style.WARNING(f'IP already blocked: {ip_str}')
                    )
                    skipped_count += 1
                    
            except ValueError:
                self.stdout.write(
                    self.style.ERROR(f'Invalid IP address: {ip_str}')
                )
                skipped_count += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error blocking IP {ip_str}: {e}')
                )
                skipped_count += 1
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Blocking complete. {blocked_count} new IPs blocked, '
                f'{skipped_count} IPs skipped.'
            )
        )
        