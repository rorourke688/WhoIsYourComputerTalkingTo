from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage

from ..models import Server, NetworkTraffic, ServersEncounteredInSession
from django.db.models import Max
import itertools
from django.db.models import Q, F

from django.db.models import Sum, Count,Value
import statistics 


def getSummaryOfSession(iterationsPerTextFile):
  traffic = ServersEncounteredInSession.objects.select_related('ip_address_fk').annotate(latitude=F('ip_address_fk__latitude'), longitude=F('ip_address_fk__longitude'), org=F('ip_address_fk__org'), ip=F('ip_address_fk__ip_address'), city=F('ip_address_fk__city'), country=F('ip_address_fk__country'), malicousCount=F('ip_address_fk__malicousCount')).exclude(latitude__isnull=True).exclude(longitude__isnull=True)

  orgs = ServersEncounteredInSession.objects.values('ip_address_fk__org').distinct()
  
  dic = []
  for org in orgs:
    maxNumberOfIterations = iterationsPerTextFile
    orgOccurences = []
    orgBytes = []
    orgServers = []

    for i in range(maxNumberOfIterations):
      allTrafficInThatIteration = traffic.filter(iterationNumber=i)
      trafficOfOrg = allTrafficInThatIteration.filter(ip_address_fk__org=org['ip_address_fk__org'])
      numberServersForOrg = trafficOfOrg.count() 
      sumOfOrgInIteration = trafficOfOrg.aggregate(Sum('total_bytes_sent'), Sum('occurrences'))
      # should be easy to add for malware
      orgOcurrences = sumOfOrgInIteration['occurrences__sum']
      orgBytesNum = sumOfOrgInIteration['total_bytes_sent__sum']

      if numberServersForOrg is None:
        numberServersForOrg = 0

      if orgOcurrences is None:
        orgOcurrences = 0

      if orgBytesNum is None:
        orgBytesNum = 0  
      
      orgOccurences.append(orgOcurrences)
      orgBytes.append(orgBytesNum)
      orgServers.append(numberServersForOrg)
    
    occurMean = statistics.mean(orgOccurences)
    occurStd = statistics.stdev(orgOccurences)

    occurStdHolder = occurStd
    occurMeanHolder = occurMean

    if occurMeanHolder == 0:
      occurMeanHolder = 1
      occurStdHolder = -1

    occurCoVariance = occurStdHolder / occurMeanHolder

    bytesMean = statistics.mean(orgBytes)
    bytesStd = statistics.stdev(orgBytes)

    bytesMeanHolder = bytesMean
    bytesStdHolder = bytesStd

    if bytesMeanHolder == 0:
      bytesMeanHolder = 1
      bytesStdHolder = -1

    bytesCoVariance = bytesStdHolder / bytesMeanHolder

    serversMean = statistics.mean(orgServers)
    serversStd = statistics.stdev(orgServers)

    serversMeanHolder = serversMean
    serversStdHolder = serversStd

    if serversMeanHolder == 0:
      serversMeanHolder = 1
      serversStdHolder = -1

    serverCoVariance = serversStdHolder / serversMeanHolder
    servermeanHolder = serversMean
    
    if servermeanHolder == 0 :
      servermeanHolder = 1
    
    traffic1 = {
      'occurrences_mean': round(occurMean, 2),
      'occurrences_std': round(occurStd,2),
      'bytes_mean': round(bytesMean, 2),
      'bytes_std': round(bytesStd,2),
      'server_mean': round(serversMean, 2),
      'server_std': round(serversStd,2),
      'bytes_co_var': round(bytesCoVariance, 4),
      'occurrences_co_var': round(occurCoVariance, 4),
      'server_co_var': round(serverCoVariance, 4),
      'occurencePerServer': round((occurMean / servermeanHolder), 4),
      'org': org['ip_address_fk__org']
    }
    
    dic.append(traffic1)
  return dic   
