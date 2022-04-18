from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage

from ..models import Server, NetworkTraffic, ServersEncounteredInSession
from django.db.models import Max
import itertools
from django.db.models import Q, F

from django.db.models import Sum, Count,Value
import statistics 


def getTrafficList():
   traffic = ServersEncounteredInSession.objects.select_related('ip_address_fk').annotate(latitude=F('ip_address_fk__latitude'), longitude=F('ip_address_fk__longitude'), org=F('ip_address_fk__org'), ip=F('ip_address_fk__ip_address'), city=F('ip_address_fk__city'), country=F('ip_address_fk__country'), malicousCount=F('ip_address_fk__malicousCount')).exclude(latitude__isnull=True).exclude(longitude__isnull=True)

   return list(traffic.values())