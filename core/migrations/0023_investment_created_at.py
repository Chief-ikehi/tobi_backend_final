# Generated by Django 5.1.2 on 2025-03-31 11:45

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0022_property_proof_of_listing'),
    ]

    operations = [
        migrations.AddField(
            model_name='investment',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
