# Generated by Django 4.0.5 on 2022-07-11 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0013_alter_otpmodel_key'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='full_name',
        ),
        migrations.AddField(
            model_name='userinformationmodel',
            name='first_name',
            field=models.CharField(default='Mr', max_length=254),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userinformationmodel',
            name='last_name',
            field=models.CharField(default='Admin', max_length=254),
            preserve_default=False,
        ),
    ]
