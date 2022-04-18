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
import json
from selenium import webdriver
from selenium.webdriver import ChromeOptions
import os
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from . import createCSV


packet_counts = Counter()

# 6 means tcp proto and 17 means udp,
# need to build an enum list https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
# get the hostname of the server
def getHostname(severIp):
    hostname = 'not found'
    try:
        hostname = socket.gethostbyaddr(str(severIp))[0]
    except socket.herror:
        hostname = 'not found'

    return hostname


def updateMalicousServerInformation(serverIP):
    endpoint = 'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=8e51d878f06a09dc24643c0b3a385eb486b96738&ip='
    response = requests.get(endpoint + str(serverIP)).json()
    
    if 'error' not in response:
        numberMalicous = response['data']['report']['blacklists']['detections']
        detectionMalicous = response['data']['report']['blacklists']['detection_rate']
        return numberMalicous, detectionMalicous
    else:
        return 0, '0%'      
      
# we cant come up with domain names on the fly as we need to wait 25 seconds for domain names
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

    # should i only display packets that are being retrieved
    #ServersEncounteredInSession.objects.update_or_create(ip_address_fk_id=destinationServer.__getattribute__('id'),
           # defaults={'tcp_count': tcp_des, 'udp_count': udp_des, 'occurrences':occ_des, 'total_bytes_sent': length_des})        

#not really used, fire fox better
def selenium_chrome(timeToSpend):
    option = ChromeOptions()
    option.add_argument("--disable-dev-shm-usage")
    option.add_argument("--disable-blink-features")
    option.add_argument("--disable-blink-features=AutomationControlled")
    option.add_argument("--disable-infobars")
    option.add_argument("user-data-dri=/Users/ryanorourke/Library/Application\ Support/Google/Chrome")
    websitesFile = open('websites.txt', 'r')
    websites = websitesFile.readlines()

    timeToWaitBetweenURls = 10
    amountOfTimeToqueryWebsites = 10
    for x in range(amountOfTimeToqueryWebsites):
        for web in websites:
            driver = webdriver.Chrome(chrome_options=option)
            driver.get(str(web.strip()))
            driver.implicitly_wait(timeToWaitBetweenURls)
            time.sleep(timeToWaitBetweenURls) 


def selenium_firefox(textfilepath, iterationsPerTextFile, timeToScan, driver, textFileName, mediaFolder, controlFile):
 contorlFileIteration = 2
 controlFileTimePerpage = 5

 websitesFile = open(textfilepath, 'r')
 websites = websitesFile.readlines()

 timeToWaitBetweenURls = timeToScan
 amountOfIterations = iterationsPerTextFile

 # for each website in the contol file we test the site x number of times then 
 # we go to the sites in the control file, from this we can see any intersting cross over

 controlFile = open(controlFile, 'r')
 controlSites = controlFile.readlines()
 # control one
 for site in controlSites:
    for i in range(contorlFileIteration):
        driver.get(str(site.strip()))
        capturePackets = sniff(timeout=controlFileTimePerpage)
        processPackets(capturePackets, i)

 controlOutputOne = textFileName + "CONTROL_OUT_BEFORE_"+".csv"
 controlSummaryOne = textFileName + "CONTROL_SUM_BEFORE"+".csv"
 createCSV.createOutputCSV(controlOutputOne, mediaFolder + "/output/controlBefore/")
 createCSV.createSummaryCSV(controlSummaryOne, mediaFolder + "/summary/controlBefore/", amountOfIterations)
 ServersEncounteredInSession.objects.all().delete()  

 for web in websites:
    name = str(web)
    name = name.replace('/','')
    name = name.replace('https:','')
    name = name.replace('.','')

    # testing the website of interest
    filenameForOutput = textFileName + "OUT_"+name+".csv"
    filenameForSummary = textFileName + "SUM_"+name+".csv"

    for i in range(amountOfIterations):
        driver.get(str(web.strip()))
        capturePackets = sniff(timeout=timeToWaitBetweenURls)
        processPackets(capturePackets, i)
    
    # create the output and summary files for the website of current interest
    createCSV.createOutputCSV(filenameForOutput, mediaFolder + "/output/")
    createCSV.createSummaryCSV(filenameForSummary, mediaFolder + "/summary/", amountOfIterations)
    ServersEncounteredInSession.objects.all().delete()

    # going back to the control to see any change
    for site in controlSites:
        for i in range(contorlFileIteration):
            driver.get(str(site.strip()))
            capturePackets = sniff(timeout=controlFileTimePerpage)
            processPackets(capturePackets, i)

    driver.close()
    controlOutput = textFileName + "CONTROL_OUT_"+name+".csv"
    controlSummary = textFileName + "CONTROL_SUM_"+name+".csv"
    createCSV.createOutputCSV(controlOutput, mediaFolder + "/output/controlAfter/")
    createCSV.createSummaryCSV(controlSummary, mediaFolder + "/summary/controlAfter/", amountOfIterations)
    ServersEncounteredInSession.objects.all().delete()        


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