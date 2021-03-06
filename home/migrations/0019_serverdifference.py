# Generated by Django 4.0.1 on 2022-03-13 22:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0018_serversencounteredinsession_iterationnumber'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServerDifference',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=255, unique=True)),
                ('country', models.CharField(max_length=255, null=True)),
                ('city', models.CharField(max_length=255, null=True)),
                ('latitude', models.FloatField(null=True)),
                ('longitude', models.FloatField(null=True)),
                ('org', models.CharField(max_length=255, null=True)),
                ('occurenceDifference', models.FloatField(null=True)),
                ('favoured', models.CharField(max_length=255, null=True)),
                ('towards', models.CharField(max_length=255, null=True)),
            ],
        ),
    ]
