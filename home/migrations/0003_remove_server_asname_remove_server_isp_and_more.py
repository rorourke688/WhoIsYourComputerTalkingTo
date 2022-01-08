# Generated by Django 4.0.1 on 2022-01-08 19:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0002_networktraffic_server_serverdomains_delete_testtable_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='server',
            name='asname',
        ),
        migrations.RemoveField(
            model_name='server',
            name='isp',
        ),
        migrations.RemoveField(
            model_name='server',
            name='organisation',
        ),
        migrations.AlterField(
            model_name='server',
            name='ip_address',
            field=models.CharField(max_length=255, unique=True),
        ),
    ]