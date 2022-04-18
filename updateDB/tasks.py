from __future__ import absolute_import, unicode_literals
from tkinter import S

from celery import shared_task
from scapy.all import *
from collections import Counter
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from django.db.models import Max, Q
from home.models import Server, NetworkTraffic, ServersEncounteredInSession, DomainNames
import requests
import time

from selenium import webdriver
from selenium.webdriver import ChromeOptions
import os
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import json


packet_counts = Counter()

def getDomainNamesForServers1(serverIP, serverID):
    dnsLink = 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=82e6d0d920f048c5d258b344722f9447f2e1a6e529e0209d3ef09a6bf471ccef&ip='
    url = dnsLink + str(serverIP)
    time.sleep(20)

    response = requests.get(url).json()
    if 'resolutions' in response:
     lengthJson = len(response['resolutions'])
     print('ip ' + str(serverIP) + ' length: ' + str(lengthJson))
     for x in range(lengthJson):
         domainName = response['resolutions'][x]['hostname']
         print('domainname: ' +str(domainName))
         DomainNames.objects.create(ip_address_fk_id=serverID, domain_name=domainName)
    else:
     print('no domain names found for ' + str(serverIP))     
  

#check the database for any public servers that has no domain names associated with it
@shared_task
def getDomainNamesForServers():
    # get the servers that are public and do not occur in the domain name table
    serversInDomainName = DomainNames.objects.values_list('ip_address_fk_id', flat=True).distinct()
    servers = Server.objects.exclude(id__in=serversInDomainName).filter(publicServer=True)

    for server in servers: 
        getDomainNamesForServers1(server.ip_address, server.id)
        time.sleep(1)          

@shared_task
def updateMalicousAllServerInformation():
 endpoint = 'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=8e51d878f06a09dc24643c0b3a385eb486b96738&ip='
 servers = Server.objects.all()

 for s in servers:
  time.sleep(1)
  if s.detectionRate is None:  
   severIp = s.ip_address
   response = requests.get(endpoint + str(severIp)).json()

   if 'error' not in response:
    numberMalicous = response['data']['report']['blacklists']['detections']
    detectionMalicous = response['data']['report']['blacklists']['detection_rate']
    print('malicous ' + str(numberMalicous))
    print('rate ' + str(detectionMalicous))
    Server.objects.filter(id=s.id).update(malicousCount=numberMalicous, detectionRate=detectionMalicous)


@shared_task
def updateObtainedServerInformation():
    endpointURL = 'https://ipapi.co/'
    apiKey = '/json'

    # any server with null information that if filled could be useful
    servers = Server.objects.all()

    for s in servers:
        severIp = s.ip_address
        source_response = requests.get(endpointURL + str(severIp) + apiKey)
        source_geodata = source_response.json()
        print(source_geodata)

        endpointURL = 'https://ipapi.co/'
        apiKey = '/json'
        append = ''
        latitideName = append + 'latitude'
        longitudeName = append + 'longitude'
        cityName = append + 'city'
        countryName = append + 'country_name'
        regionName = append + 'region'
        asnName = append + 'asn'
        orgName = append + 'org'
        errorName = append + 'error'

        serverIDValue = s.id
        
        # if no error occured
        if errorName not in source_geodata:

            if source_geodata[latitideName] is not None and source_geodata[longitudeName] is not None:
                Server.objects.filter(id=serverIDValue).update(latitude=source_geodata[latitideName], longitude=source_geodata[longitudeName])

            if source_geodata[countryName] is not None:
                Server.objects.filter(id=serverIDValue).update(country=source_geodata[countryName])   

            if source_geodata[cityName] is not None:
                Server.objects.filter(id=serverIDValue).update(city=source_geodata[cityName])

            if source_geodata[regionName] is not None:
                Server.objects.filter(id=serverIDValue).update(region=source_geodata[regionName])

            if source_geodata[asnName] is not None:
                Server.objects.filter(id=serverIDValue).update(asn=source_geodata[asnName])
                            
            if source_geodata[orgName] is not None:
                Server.objects.filter(id=serverIDValue).update(org=source_geodata[orgName])
        else:
            Server.objects.filter(id=serverIDValue).update(publicServer=False)

        print('about to sleep')
        time.sleep(2)                                    

            
          

 




  