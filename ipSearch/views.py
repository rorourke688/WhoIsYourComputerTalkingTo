from django.core.checks import messages
from django.core.files.storage import FileSystemStorage
from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse

from ipSearch.models import dataPacket

# this method handles uploading a csv into the datapackets table
def upload(request):
 if request.method == 'POST':
  upload_file = request.FILES['document']
  
  # TODO : fix, this file check doesnt work
  if not upload_file.name.endswith('.csv'):
   messages.WARNING(request, 'The wrong file type has been uploaded. CSV is needed')
   return HttpResponseRedirect(request.path.info)

  file_data = upload_file.read().decode('utf-8')
  csv_data = file_data.split('\n')
  csv_data = list(filter(None, csv_data))

  for row in csv_data:
   fields = row.split(',')
   created = dataPacket.objects.create(source_IP=fields[2], destination_IP=fields[3], info=fields[6])
  
 return render(request, 'upload.html')