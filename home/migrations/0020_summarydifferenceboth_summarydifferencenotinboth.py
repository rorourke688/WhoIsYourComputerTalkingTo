# Generated by Django 4.0.1 on 2022-03-15 19:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0019_serverdifference'),
    ]

    operations = [
        migrations.CreateModel(
            name='SummaryDifferenceBoth',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('org', models.CharField(max_length=255, null=True)),
                ('fileOneOccurPerServer', models.FloatField(null=True)),
                ('fileTwoOccurPerServer', models.FloatField(null=True)),
                ('differenceInOccurPerServer', models.FloatField(null=True)),
                ('differenceInCoefficentOfStd', models.FloatField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='SummaryDifferenceNotInBoth',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('org', models.CharField(max_length=255, null=True)),
                ('occurrencePerServer', models.FloatField(null=True)),
                ('coefficentOfStd', models.FloatField(null=True)),
            ],
        ),
    ]
