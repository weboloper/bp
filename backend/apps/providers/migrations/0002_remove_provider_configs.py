# Generated manually - Remove provider config models

from django.db import migrations


class Migration(migrations.Migration):
    """
    Remove SMSProviderConfig and EmailProviderConfig models.
    Provider configuration is now managed via settings (env-based).
    """

    dependencies = [
        ('providers', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='EmailProviderConfig',
        ),
        migrations.DeleteModel(
            name='SMSProviderConfig',
        ),
    ]
