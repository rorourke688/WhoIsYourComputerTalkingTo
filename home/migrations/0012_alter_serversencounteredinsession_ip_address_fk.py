# Generated by Django 4.0.1 on 2022-01-15 12:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0011_alter_serversencounteredinsession_ip_address_fk'),
    ]

    operations = [
        migrations.AlterField(
            model_name='serversencounteredinsession',
            name='ip_address_fk',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='home.server'),
        ),
    ]
