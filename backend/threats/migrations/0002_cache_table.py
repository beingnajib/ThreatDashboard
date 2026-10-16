from django.core.management import call_command
from django.db import migrations


def create_cache_table(apps, schema_editor):
    # Creates the DatabaseCache table used for shared rate-limit counters.
    # No-op for non-database cache backends and when the table already exists.
    call_command("createcachetable", database=schema_editor.connection.alias, verbosity=0)


class Migration(migrations.Migration):
    dependencies = [("threats", "0001_initial")]

    operations = [migrations.RunPython(create_cache_table, migrations.RunPython.noop)]
