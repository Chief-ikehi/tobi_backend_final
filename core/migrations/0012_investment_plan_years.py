# Generated by Django 5.1.7 on 2025-03-27 20:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0011_privatemembership'),
    ]

    operations = [
        migrations.AddField(
            model_name='investment',
            name='plan_years',
            field=models.IntegerField(default=2),
        ),
    ]
