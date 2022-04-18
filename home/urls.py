from django import urls
from django.conf import Settings, settings
from django.urls import path

from django.views.generic import TemplateView
from . models import Server
from djgeojson.views import GeoJSONLayerView

from . import views
from sniffer import tasks

# url configuration
urlpatterns = [
 path('', TemplateView.as_view(template_name='index.html')),
 path('uploadSummary/', views.uploadSummary, name='uploadSummary'),
 path('csvOrgSummaryDifference/', TemplateView.as_view(template_name='compareOrgSummary.html')),
 path('getSummaryInFileTwo/', views.getSummaryInFileTwo, name='getSummaryInFileTwo'),
 path('getNewServerTraffic/', views.getNewServerTraffic, name='getNewServerTraffic'),
 path('csvSummary/', TemplateView.as_view(template_name='csvSummary.html')),
 path('deleteAllRowsInNetworkTraffic/', views.deleteAllRowsInNetworkTraffic, name='deleteAllRowsInNetworkTraffic'),
 path('scanControlWebsites/', views.scanWebsitesControl, name='scanControlWebsites'),
 path('scanWebsites/', views.scanWebsitesInSingleFile, name='scanWebsites'),
 path('getServerDifferences/', views.getServerDifferences, name='getServerDifferences'),
 path('getServerDifferencesSummary/', views.getServerDifferencesSummary, name='getServerDifferencesSummary'),
 path('upload/', views.upload, name='upload'),
 path('getSummaryInBoth/', views.getSummaryInBoth, name='getSummaryInBoth'),
 path('getSummaryInFileOne/', views.getSummaryInFileOne, name='getSummaryInFileOne'),
 path('outputAllSummaryFiles/', views.outputAllSummaryFiles, name='outputAllSummaryFiles')
]