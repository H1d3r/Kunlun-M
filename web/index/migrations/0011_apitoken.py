import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("index", "0010_scantask_webscan_fields"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ApiToken",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(blank=True, default="", help_text="Token 用途备注", max_length=100)),
                ("token", models.CharField(db_index=True, max_length=64, unique=True)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("user", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="api_tokens", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "web_apitoken",
                "verbose_name": "API Token",
                "verbose_name_plural": "API Tokens",
            },
        ),
    ]
