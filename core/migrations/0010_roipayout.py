# Generated by Django 5.1.7 on 2025-03-27 19:37

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_investment'),
    ]

    operations = [
        migrations.CreateModel(
            name='ROIPayout',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('payout_date', models.DateField(auto_now_add=True)),
                ('amount_paid', models.DecimalField(decimal_places=2, max_digits=15)),
                ('investment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='roi_payouts', to='core.investment')),
            ],
        ),
    ]
