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

def getDomainNamesForServers(serverIP, serverID):
    dnsLink1 = 'https://dns-history.whoisxmlapi.com/api/v1?apiKey=at_31sSHsR0AaUcNc1oZFnH9xZ57l8Z0&ip='
    dnsLink = 'https://dns-history.whoisxmlapi.com/api/v1?apiKey=at_WYnnHJDmCHkCHYQSOyuocEKOiBEya&ip='

    url = dnsLink + str(serverIP)
    response = requests.get(url).json()
    numberToIterate = response['size']
    resultList = response['result']

    for x in range(numberToIterate):
        row = resultList[x]
        domainName = row['name']
        DomainNames.objects.create(ip_address_fk_id=serverID, domain_name=domainName)  

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
            
            country = source_geodata[countryName]
            city = source_geodata[cityName]
            
            # design consideration, if lat and long dont exis we still add to the serer table, 457
            if source_geodata[latitideName] is not None and source_geodata[longitudeName] is not None:
                lat = float(source_geodata[latitideName])
                long = float(source_geodata[longitudeName])

                if source_geodata[orgName] is not None and source_geodata[asnName] is not None:
                    Server.objects.create(ip_address=str(severIp), country=country, city=city, latitude=lat, longitude=long, hostname=hostname, asn=source_geodata[asnName], org=source_geodata[orgName], region=source_geodata[regionName])
                else:
                    Server.objects.create(ip_address=str(severIp), country=country, city=city, latitude=lat, longitude=long, hostname=hostname)    
            else:
                Server.objects.create(ip_address=str(severIp), country=country, city=city, hostname=hostname)

            serverID = Server.objects.get(ip_address=str(severIp)).id
            getDomainNamesForServers(severIp, serverID)
        else:
             Server.objects.create(ip_address=str(severIp), hostname=hostname, publicServer=False)
    else:
        print('ip address is already in the table: ' + str(severIp))

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

def IPOccurrenceUpdate(sourceServer, tcp, udp, l):
    sourceOccurr = ServersEncounteredInSession.objects.filter(ip_address_fk_id=sourceServer.__getattribute__('id')).first()
    tcp_count = tcp
    udp_count = udp
    length = l
    occurrences = 1

    if sourceOccurr is not None:
        tcp_count = tcp_count +  sourceOccurr.__getattribute__('tcp_count')
        udp_count = udp_count +  sourceOccurr.__getattribute__('udp_count')
        occurrences = occurrences + sourceOccurr.__getattribute__('occurrences')
        length = length + sourceOccurr.__getattribute__('total_bytes_sent')

    ServersEncounteredInSession.objects.update_or_create(ip_address_fk_id=sourceServer.__getattribute__('id'),
            defaults={'tcp_count': tcp_count, 'udp_count': udp_count, 'occurrences':occurrences, 'total_bytes_sent': length})


def readFile(row, name):
    return "https://stackoverflow.com/questions/13218213/django-tutorial-setting-the-correct-path-variable"


@shared_task
def selenium_chrome():
    option = ChromeOptions()
    option.add_argument("--disable-dev-shm-usage")
    option.add_argument("--disable-blink-features")
    option.add_argument("--disable-blink-features=AutomationControlled")
    option.add_argument("--disable-infobars")
    option.add_argument("user-data-dri=/Users/ryanorourke/Library/Application\ Support/Google/Chrome")
    websitesFile = open('websites.txt', 'r')
    websites = websitesFile.readlines()

    timeToWaitBetweenURls = 10
    amountOfTimeToqueryWebsites = 1
    for x in range(amountOfTimeToqueryWebsites):
        for web in websites:
            driver = webdriver.Chrome(chrome_options=option)
            driver.get(str(web.strip()))
            driver.implicitly_wait(timeToWaitBetweenURls)
            time.sleep(timeToWaitBetweenURls) 

# fire fox is good as it rememebers logins, chrome seems to not as it knows a bot is accessing the browser
@shared_task
def selenium_firefox():
    profile = webdriver.FirefoxProfile('/Users/ryanorourke/Library/Application Support/Firefox/Profiles/1z91fxqr.default-release')
    profile.set_preference("dom.webdriver.enabled", False)
    profile.set_preference('useAutomationExtension', False)
    profile.update_preferences()
    desired = DesiredCapabilities.FIREFOX

    driver = webdriver.Firefox(firefox_profile=profile,
                           desired_capabilities=desired)

    websitesFile = open('websites.txt', 'r')
    websites = websitesFile.readlines()

    timeToWaitBetweenURls = 2
    amountOfTimeToqueryWebsites = 1
    for web in websites:
        driver.get(str(web.strip()))
        driver.implicitly_wait(timeToWaitBetweenURls)
        time.sleep(timeToWaitBetweenURls)

    driver.quit()

@shared_task
def statement():
 schedualNumber = NetworkTraffic.objects.aggregate(Max('schedule_number'))['schedule_number__max']

 if schedualNumber is None:
     schedualNumber = 1
 else:
     schedualNumber = schedualNumber + 1   

 print('The number is ' + str(schedualNumber))      
 capture = sniff(timeout=5)
 for packet in capture:
    if hasattr(packet.payload, "src") and hasattr(packet.payload, "dst") and hasattr(packet.payload, "proto") and hasattr(packet.payload, "len"): 
        sourceIP = packet[0][1].src
        destinationIP = packet[0][1].dst
        length = packet[0][1].len
        protocol = packet[0][1].proto

        # need a new endpoint
        addServerToDb(sourceIP)
        addServerToDb(destinationIP)
        
        sourceServer = Server.objects.filter(ip_address=str(sourceIP)).first()
        destinationServer = Server.objects.filter(ip_address=str(destinationIP)).first()

        if sourceServer is not None and destinationServer is not None:
            protocolState = getProtol(protocol)
            tcp_count = protocolId(protocolState, NetworkTraffic.PROTOCOL_TCP)
            udp_count = protocolId(protocolState, NetworkTraffic.PROTOCOL_UDP)

            IPOccurrenceUpdate(sourceServer, tcp_count, udp_count, length)
            IPOccurrenceUpdate(destinationServer, tcp_count, udp_count, length)      

#check the database for any public servers that has no domain names associated with it
@shared_task
def getDomainNamesForServers():
    # get the servers that are public and do not occur in the domain name table
    serversInDomainName = DomainNames.objects.values_list('ip_address_fk_id', flat=True).distinct()
    servers = Server.objects.exclude(id__in=serversInDomainName).filter(publicServer=True)

    for server in servers: 
        getDomainNamesForServers(server.ip_address, server.id)
        time.sleep(1)          

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

            
          

 




  