from re import T
from django.db import models
from django.utils.translation import gettext_lazy as _

# the Server tabe doesnt need to be deleted at the end of each session

class Server(models.Model):
 ip_address = models.CharField(max_length=255, unique=True)
 country = models.CharField(max_length=255, null=True)
 city = models.CharField(max_length=255, null=True)
 latitude = models.FloatField()
 longitude = models.FloatField()
 hostname = models.CharField(max_length=255, null=True)

###### following tables should be cleaned after each session  ########

# domain names seen in a session relating to a particular server
class ServerDomains(models.Model):
 ip_address = models.CharField(max_length=255)
 domainName = models.CharField(max_length=255)

# all the netowrk traffic seen in a session
class NetworkTraffic(models.Model):
 PROTOCOL_DEFAULT = -1
 PROTOCOL_UDP = 17
 PROTOCOL_TCP = 6
 
 PROTOCOL_CHOICES = [
  (PROTOCOL_TCP, 'TCP'),
  (PROTOCOL_UDP, 'UDP'),
  (PROTOCOL_DEFAULT, 'NONE')
 ]

 source_address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='source', null=True)
 destination_Address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='destination', null=True)
 protocol = models.CharField(choices=PROTOCOL_CHOICES, default=PROTOCOL_DEFAULT, max_length=255)
 length_Bytes = models.PositiveIntegerField()
 schedule_number = models.BigIntegerField()
 
# future tables refard white and black lists needs to be created
