from django.conf import Settings, settings
from django.urls import path
from . import views

# url configuration
urlpatterns = [
 path('upload/', views.upload, name='upload')
]