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

@shared_task
def add(x, y):
 return x + y

packet_counts = Counter()

# 6 means tcp proto and 17 means udp,
# need to build an enum list https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

# NetworkTraffic.objects.create(source_address_fk=sourceServer, destination_Address_fk=destinationServer, protocol=protocolState, length_Bytes=length, schedule_number=schedualNumber)

# get the hostname of the server
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


# probably execute this method every 30 secs of 1 mins
@shared_task
def getDomainNamesForServers():
    dnsLink1 = 'https://dns-history.whoisxmlapi.com/api/v1?apiKey=at_31sSHsR0AaUcNc1oZFnH9xZ57l8Z0&ip='
    dnsLink = 'https://dns-history.whoisxmlapi.com/api/v1?apiKey=at_WYnnHJDmCHkCHYQSOyuocEKOiBEya&ip='
    
    # get the servers that are public and do not occur in the domain name table
    serversInDomainName = DomainNames.objects.values_list('ip_address_fk_id', flat=True).distinct()
    servers = Server.objects.exclude(id__in=serversInDomainName).filter(publicServer=True)

    # do the domain name rest call to get the json
    # we now have a list of domain names, iterate over these names create methods for check black list and white list table
    # these methods will be created later
    # create in row in the databases

    for server in servers:        
        url = dnsLink + str(server.ip_address)
        response = requests.get(url).json()
        numberToIterate = response['size']
        resultList = response['result']
        print(numberToIterate)

        for x in range(numberToIterate):
            row = resultList[x]
            domainName = row['name']
            DomainNames.objects.create(ip_address_fk_id=server.id, domain_name=domainName)

        print("sleeping")
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

            
          

 




  