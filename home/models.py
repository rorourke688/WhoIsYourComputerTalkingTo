from re import T
from django.db import models
from django.utils.translation import gettext_lazy as _

# the Server tabe doesnt need to be deleted at the end of each session

class Server(models.Model):
 ip_address = models.CharField(max_length=255, unique=True)
 country = models.CharField(max_length=255, null=True)
 city = models.CharField(max_length=255, null=True)
 latitude = models.FloatField(null=True)
 longitude = models.FloatField(null=True)
 hostname = models.CharField(max_length=255, null=True)
 asn = models.CharField(max_length=255, null=True)
 org = models.CharField(max_length=255, null=True)
 region = models.CharField(max_length=255, null=True)
 publicServer = models.BooleanField(default=True, null=True)
 malicousCount = models.IntegerField(default=0, null=True)
 detectionRate = models.CharField(max_length=255, null=True)

class DomainNames(models.Model):
  ip_address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, null=True)
  domain_name = models.CharField(max_length=255, null=True)
  black_list_occur =  models.PositiveIntegerField(null=True)
  white_list_occur =  models.PositiveIntegerField(null=True)

class ServersEncounteredInSession(models.Model):
  ip_address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, null=True)
  occurrences =  models.BigIntegerField(default=0)
  tcp_count = models.BigIntegerField(default=0)
  udp_count = models.BigIntegerField(default=0)
  total_bytes_sent = models.BigIntegerField(default=0)
  iterationNumber = models.PositiveIntegerField(null=True)

# all the netowrk traffic seen in a session
class NetworkTraffic(models.Model):
 PROTOCOL_UDP = 'UDP'
 PROTOCOL_TCP = 'TCP'
 PROTOCOL_NOTLISTED = 'NOT LISTED'

 source_address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='source', null=True)
 destination_Address_fk = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='destination', null=True)
 protocol = models.CharField(max_length=255)
 length_Bytes = models.PositiveIntegerField()
 schedule_number = models.BigIntegerField()
 
# future tables refard white and black lists needs to be created

class ServerDifference(models.Model):
 ip_address = models.CharField(max_length=255, unique=True)
 country = models.CharField(max_length=255, null=True)
 city = models.CharField(max_length=255, null=True)
 latitude = models.FloatField(null=True)
 longitude = models.FloatField(null=True)
 org = models.CharField(max_length=255, null=True)
 occurenceDifference = models.FloatField(null=True)
 favoured = models.CharField(max_length=255, null=True)
 towards = models.CharField(max_length=255, null=True) 

class SummaryDifferenceBoth(models.Model):
  org = models.CharField(max_length=255, null=True)
  fileOneOccurrences_mean = models.FloatField(null=True)
  fileTwoOccurrences_mean = models.FloatField(null=True)
  differenceInOccurenceMean = models.FloatField(null=True)

class SummaryDifferenceNotInBoth(models.Model):
  org = models.CharField(max_length=255, null=True)
  occurrences_mean = models.FloatField(null=True)
  fileNumber = models.SmallIntegerField(null=True)