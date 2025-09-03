"""
Create superuser with environment variables
Usage: python manage.py create_admin
"""
import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Create superuser from environment variables'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Admin username')
        parser.add_argument('--email', type=str, help='Admin email')
        parser.add_argument('--password', type=str, help='Admin password')

    def handle(self, *args, **options):
        User = get_user_model()
        
        # Get credentials from arguments or environment
        username = options.get('username') or os.environ.get('ADMIN_USERNAME', 'admin')
        email = options.get('email') or os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        password = options.get('password') or os.environ.get('ADMIN_PASSWORD', 'admin123')
        
        # Check if admin already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'User "{username}" already exists')
            )
            return
        
        # Create superuser
        try:
            User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created superuser "{username}"')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating superuser: {str(e)}')
            )