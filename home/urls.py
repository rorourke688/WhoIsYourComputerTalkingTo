from django import urls
from django.conf import Settings, settings
from django.urls import path

from django.views.generic import TemplateView
from . models import Server
from djgeojson.views import GeoJSONLayerView

from . import views

# url configuration
urlpatterns = [
 # path('upload/', views.upload, name='upload')
 path('geo', TemplateView.as_view(template_name='index.html')),
 path('getAllservers/', views.getAllServers, name='getAllservers'),
 path('getNewServerTraffic/', views.getNewServerTraffic, name='getNewServerTraffic'),
 path('deleteAllRowsInNetworkTraffic/', views.deleteAllRowsInNetworkTraffic, name='deleteAllRowsInNetworkTraffic')
 #path('map', GeoJSONLayerView.as_view(model=Server))
]