from __future__ import absolute_import, unicode_literals

from celery import shared_task
from scapy.all import *
from collections import Counter
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP

from home.models import Server, NetworkTraffic, ServerDomains
import requests

@shared_task
def add(x, y):
 return x + y

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

def addServerToDb(severIp):
    append = 'geoplugin_'
    endpointURL = 'http://www.geoplugin.net/json.gp?ip='

    # if the server is in the db we dont need to query the endpoint
    if Server.objects.filter(ip_address=str(severIp)).exists() is False:
        print(str(severIp))
        source_response = requests.get(endpointURL + str(severIp))
        source_geodata = source_response.json()
        
        # if lat and long doesnt exist then we cant add as this is the important detail
        if source_geodata[append + 'latitude'] is not None and source_geodata[append + 'longitude'] is not None:
            country = source_geodata[append + 'countryName']
            city = source_geodata[append + 'city']
            lat = float(source_geodata[append + 'latitude'])
            long = float(source_geodata[append +'longitude'])
            hostname = getHostname(str(severIp))

            Server.objects.update_or_create(ip_address=str(severIp), country=country, city=city, latitude=lat, longitude=long, hostname=hostname)

@shared_task
def statement():
 capture = sniff(count=15)
 for packet in capture:
    if hasattr(packet.payload, "src") and hasattr(packet.payload, "dst"): 
        sourceIP = packet[0][1].src
        destinationIP = packet[0][1].dst
        #length = packet[0][1].len
        #protocol = packet[0][1].proto  i think there was an issue here
        
        addServerToDb(sourceIP)
        addServerToDb(destinationIP)

            


 ## Print out packet count per A <--> Z address pair
 #print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items())) 


 




  