from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from celery import shared_task
from scapy.all import *
from collections import Counter
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from django.db.models import Max, Q
from home.models import Server, NetworkTraffic, ServersEncounteredInSession, DomainNames
import requests
import time
import json
from selenium import webdriver
import os
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from ... import createCSV

def getFileName(name):
  controlname = str(name)
  controlname = controlname.replace('.com','')
  controlname = controlname.replace('.co.uk','')
  controlname = controlname.replace('.org','')
  controlname = controlname.replace('.tv','')
  controlname = controlname.replace('/home/index.html','')
  controlname = controlname.replace('/','')
  controlname = controlname.replace('https:','')
  controlname = controlname.replace('.','')
  controlname = controlname.replace('www','')
  controlname = controlname.replace('us','')
  controlname = controlname.replace('\n','')
  return controlname

def iterateThroughPage(iteration, driver, site, timePerpage):
 for i in range(iteration):
  driver.get(str(site.strip()))
  time.sleep(1)
  capturePackets = sniff(timeout=timePerpage)
  processPackets(capturePackets, i)

# returns a Firefox driver instance that can be either closed or used to browse website(s)
def getSeleniumFireFoxDriver():
  fireforxProfilePath = '/Users/ryanorourke/Library/Application Support/Firefox/Profiles/1z91fxqr.default-release'
  profile = webdriver.FirefoxProfile(fireforxProfilePath)
  profile.set_preference("dom.webdriver.enabled", True)
  # we will use firefox privacy windows. If we want normal ones we can comment this line out
  profile.set_preference("browser.privatebrowsing.autostart", True)
  profile.set_preference("useAutomationExtension", True)
  profile.set_preference("extensions.firebug.onByDefault", True)
  profile.update_preferences()
  desired = DesiredCapabilities.FIREFOX

  driver = webdriver.Firefox(firefox_profile=profile,desired_capabilities=desired)
  return driver

def getProtol(number):
 if number == 6:
     return NetworkTraffic.PROTOCOL_TCP

 if number == 17:
     return NetworkTraffic.PROTOCOL_UDP

 return str(number)   

def protocolId(protocolType, obtainedProtocol):
 if obtainedProtocol == protocolType:
     return 1
 else:
     return 0  

def IPOccurrenceUpdate(sourceServer, destinationServer, tcp, udp, l, iterationNumber):
    sourceOccurr = ServersEncounteredInSession.objects.filter(ip_address_fk_id=sourceServer.__getattribute__('id')).first()
    desOccurr = ServersEncounteredInSession.objects.filter(ip_address_fk_id=destinationServer.__getattribute__('id')).first()
    
    tcp_count = tcp
    udp_count = udp

    tcp_src = tcp_count
    tcp_des = tcp_count

    udp_src = udp_count
    udp_des = udp_count

    occ_src = 1
    occ_des = 1

    length_src = l
    length_des = l

    if sourceOccurr is not None:
        tcp_src = tcp_src +  sourceOccurr.__getattribute__('tcp_count')
        udp_src = udp_src +  sourceOccurr.__getattribute__('udp_count')
        occ_src = occ_src + sourceOccurr.__getattribute__('occurrences')
        length_src = length_src + sourceOccurr.__getattribute__('total_bytes_sent')

    if desOccurr is not None:
        tcp_des = tcp_des +  desOccurr.__getattribute__('tcp_count')
        udp_des = udp_des +  desOccurr.__getattribute__('udp_count')
        occ_des = occ_des + desOccurr.__getattribute__('occurrences')
        length_des = length_des + desOccurr.__getattribute__('total_bytes_sent')    

    ServersEncounteredInSession.objects.update_or_create(ip_address_fk_id=sourceServer.__getattribute__('id'),
            defaults={'tcp_count': tcp_src, 'udp_count': udp_src, 'occurrences':occ_src, 'total_bytes_sent': length_src, 'iterationNumber': iterationNumber})

def updateMalicousServerInformation(serverIP):
    endpoint = 'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=8e51d878f06a09dc24643c0b3a385eb486b96738&ip='
    response = requests.get(endpoint + str(serverIP)).json()

    if 'error' not in response:
        numberMalicous = response['data']['report']['blacklists']['detections']
        detectionMalicous = response['data']['report']['blacklists']['detection_rate']
        return numberMalicous, detectionMalicous
    else:
        return 0, '0%' 

def getHostname(severIp):
    hostname = 'not found'
    try:
        hostname = socket.gethostbyaddr(str(severIp))[0]
    except socket.herror:
        hostname = 'not found'

    return hostname
    
def addServerToDb(severIp):
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

    # add org and asn columns
    hostname = getHostname(str(severIp))

    # if the server is in the db we dont need to query the endpoint
    if not Server.objects.filter(ip_address=str(severIp)).exists():
     source_response = requests.get(endpointURL + str(severIp) + apiKey)
     source_geodata = source_response.json()

     # if error is in json the correct one hasnt been returned
     if errorName not in source_geodata:
      result = updateMalicousServerInformation(severIp)
      malicousCount = result[0]
      malicousDetectionRate = result[1]
      country = source_geodata[countryName]
      city = source_geodata[cityName]
      
         
      # design consideration, if lat and long dont exis we still add to the serer table, 457
      if source_geodata[latitideName] is not None and source_geodata[longitudeName] is not None:
       lat = float(source_geodata[latitideName])
       long = float(source_geodata[longitudeName])

       if source_geodata[orgName] is not None and source_geodata[asnName] is not None:
           Server.objects.create(ip_address=str(severIp), country=country, city=city, latitude=lat, longitude=long, hostname=hostname, asn=source_geodata[asnName], org=source_geodata[orgName], region=source_geodata[regionName], malicousCount=malicousCount, detectionRate=malicousDetectionRate)
       else:
           Server.objects.create(ip_address=str(severIp), country=country, city=city, latitude=lat, longitude=long, hostname=hostname, malicousCount=malicousCount, detectionRate=malicousDetectionRate)    
      else:
         Server.objects.create(ip_address=str(severIp), country=country, city=city, hostname=hostname, malicousCount=malicousCount, detectionRate=malicousDetectionRate)
     else:
         Server.objects.create(ip_address=str(severIp), hostname=hostname, publicServer=False)
    else:
     print('existing server')


def processPackets(capturedPackets, iterationNumber):   
 for packet in capturedPackets:
    if hasattr(packet.payload, "src") and hasattr(packet.payload, "dst") and hasattr(packet.payload, "proto") and hasattr(packet.payload, "len"): 
        sourceIP = packet[0][1].src
        destinationIP = packet[0][1].dst
        length = packet[0][1].len
        protocol = packet[0][1].proto

        addServerToDb(sourceIP)
        addServerToDb(destinationIP)
        
        # get the servers from the database as they were just saved
        sourceServer = Server.objects.filter(ip_address=str(sourceIP)).first()
        destinationServer = Server.objects.filter(ip_address=str(destinationIP)).first()

        if sourceServer is not None and destinationServer is not None:
            protocolState = getProtol(protocol)
            tcp_count = protocolId(protocolState, NetworkTraffic.PROTOCOL_TCP)
            udp_count = protocolId(protocolState, NetworkTraffic.PROTOCOL_UDP)

            IPOccurrenceUpdate(sourceServer, destinationServer, tcp_count, udp_count, length, iterationNumber)