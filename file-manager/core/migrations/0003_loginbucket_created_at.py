from django.db import migrations, models
from django.utils import timezone


class Migration(migrations.Migration):
    dependencies = [("core", "0002_auditevent_session_tag")]
    operations = [
        migrations.AddField(
            model_name="loginbucket",
            name="created_at",
            field=models.DateTimeField(
                auto_now_add=True, db_index=True, default=timezone.now
            ),
            preserve_default=False,
        ),
    ]
