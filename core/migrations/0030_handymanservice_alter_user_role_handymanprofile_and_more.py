# Generated by Django 5.1.7 on 2025-04-25 11:00

import core.models
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0029_pendinginvestment'),
    ]

    operations = [
        migrations.CreateModel(
            name='HandymanService',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
                ('icon', models.CharField(blank=True, help_text="Icon class name (e.g., 'fa-wrench')", max_length=50, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('customer', 'Customer'), ('investor', 'Investor'), ('agent', 'Agent'), ('handyman', 'Handyman'), ('admin', 'Admin'), ('superadmin', 'Superadmin')], default='customer', max_length=20),
        ),
        migrations.CreateModel(
            name='HandymanProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bio', models.TextField(blank=True, null=True)),
                ('experience_years', models.PositiveIntegerField(default=0)),
                ('hourly_rate', models.DecimalField(decimal_places=2, max_digits=10)),
                ('is_available', models.BooleanField(default=True)),
                ('valid_id', models.FileField(blank=True, null=True, upload_to=core.models.handyman_directory_path)),
                ('certification', models.FileField(blank=True, null=True, upload_to=core.models.handyman_directory_path)),
                ('proof_of_work', models.FileField(blank=True, null=True, upload_to=core.models.handyman_directory_path)),
                ('status', models.CharField(choices=[('unverified', 'Unverified'), ('pending', 'Pending Review'), ('verified', 'Verified')], default='unverified', max_length=20)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('service_area', models.CharField(blank=True, max_length=100, null=True)),
                ('profile_image', models.URLField(blank=True, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='handyman_profile', to=settings.AUTH_USER_MODEL)),
                ('services', models.ManyToManyField(related_name='handymen', to='core.handymanservice')),
            ],
        ),
        migrations.CreateModel(
            name='ServiceRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.TextField()),
                ('requested_date', models.DateField()),
                ('requested_time', models.TimeField()),
                ('estimated_hours', models.PositiveIntegerField(default=1)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='pending', max_length=20)),
                ('total_cost', models.DecimalField(blank=True, decimal_places=2, max_digits=10, null=True)),
                ('payment_status', models.CharField(choices=[('unpaid', 'Unpaid'), ('paid', 'Paid')], default='unpaid', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('customer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_requests', to=settings.AUTH_USER_MODEL)),
                ('handyman', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_jobs', to=settings.AUTH_USER_MODEL)),
                ('property_booking', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='service_requests', to='core.booking')),
                ('service', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.handymanservice')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
