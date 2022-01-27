from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage

from .models import Server, NetworkTraffic, ServersEncounteredInSession
from django.db.models import Max
import itertools
from django.db.models import Q, F

# Create your views here.

def upload(request):
 context = {}
 if request.method == 'POST':
  upload_file = request.FILES['document']
  fs = FileSystemStorage()
  name = fs.save(upload_file.name, upload_file)
  context['url'] = fs.url(name)
 return render(request, 'upload.html', context)


# getting all the markers in one session
def getAllMarkers(request):
 print('')


#getting all the markers taken in one celery task operation
def getMarkers(request):
 print('')


def getAllServers(request):
 servers = Server.objects.all().filter(latitude__isnull=False)
 return JsonResponse({"servers": list(servers.values())})


# TODO in order to be efficent with data, once the max schedual is found the 
# intances not that schedule are deleted
def getNewServerTraffic(request):  

  traffic = ServersEncounteredInSession.objects.select_related('ip_address_fk').annotate(latitude=F('ip_address_fk__latitude'), longitude=F('ip_address_fk__longitude'), hostname=F('ip_address_fk__hostname'), city=F('ip_address_fk__city'), country=F('ip_address_fk__country')).exclude(latitude__isnull=True).exclude(longitude__isnull=True)
  
  return JsonResponse({"servers": list(traffic.values())})

def deleteAllRowsInNetworkTraffic(request):
  ServersEncounteredInSession.objects.all().delete()
  return HttpResponse('Network Traffic Deleted from database')




