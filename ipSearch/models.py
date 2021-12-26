from django.db import models

# Create your models here.

class dataPacket(models.Model):
 source_IP = models.CharField(max_length=100)
 destination_IP = models.CharField(max_length=100)
 info = models.TextField()
