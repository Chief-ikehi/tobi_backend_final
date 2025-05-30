# Generated by Django 5.1.7 on 2025-03-27 16:37

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_rename_property_gift_gifted_property'),
    ]

    operations = [
        migrations.CreateModel(
            name='Investment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount_invested', models.DecimalField(decimal_places=2, max_digits=15)),
                ('investment_date', models.DateField(auto_now_add=True)),
                ('roi_percentage', models.FloatField(default=5.0)),
                ('active', models.BooleanField(default=True)),
                ('investor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='investments', to=settings.AUTH_USER_MODEL)),
                ('property', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.property')),
            ],
        ),
    ]
