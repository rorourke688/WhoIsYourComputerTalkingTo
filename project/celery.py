from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')

app = Celery('project')
app.config_from_object('django.conf:settings', namespace='CODE')

app.conf.beat_schedule = {
 'ever-10-seconds': {
   'task': 'sniffer.tasks.statement',
   'schedule': 30,
   'args': ()
 }
}

app.autodiscover_tasks()