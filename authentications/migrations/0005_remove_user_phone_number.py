# Generated by Django 3.2.6 on 2021-08-07 06:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentications', '0004_user_phone_number'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='phone_number',
        ),
    ]