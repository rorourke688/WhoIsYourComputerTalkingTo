from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage

from .models import SummaryDifferenceBoth, SummaryDifferenceNotInBoth
from django.db.models import Max
import itertools
from django.db.models import Q, F


def getSummaryOrgsInBoth():
   traffic = SummaryDifferenceBoth.objects.all()
   return list(traffic.values())

def getSummaryOrgsInFile(filenumber):
   traffic = SummaryDifferenceNotInBoth.objects.all().filter(fileNumber=int(filenumber))
   return list(traffic.values())   