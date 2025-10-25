"""
Generate secret key command
Usage: python manage.py generate_secret_key
"""
from django.core.management.base import BaseCommand
from django.core.management.utils import get_random_secret_key


class Command(BaseCommand):
    help = 'Generate a new Django secret key'

    def add_arguments(self, parser):
        parser.add_argument(
            '--length',
            type=int,
            default=50,
            help='Length of the secret key (default: 50)',
        )

    def handle(self, *args, **options):
        secret_key = get_random_secret_key()
        
        self.stdout.write('Copy this secret key to your .env file:')
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(f'SECRET_KEY={secret_key}'))
        self.stdout.write('')
        self.stdout.write('⚠️  Keep this secret and never commit it to version control!')