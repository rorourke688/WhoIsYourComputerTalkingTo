# Generated by Django 4.0.1 on 2022-01-25 20:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0013_server_asn_server_org'),
    ]

    operations = [
        migrations.AddField(
            model_name='server',
            name='region',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
