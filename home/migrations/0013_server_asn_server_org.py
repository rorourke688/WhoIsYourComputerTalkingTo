# Generated by Django 4.0.1 on 2022-01-25 20:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0012_alter_serversencounteredinsession_ip_address_fk'),
    ]

    operations = [
        migrations.AddField(
            model_name='server',
            name='asn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='server',
            name='org',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
