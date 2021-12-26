from django.urls import path
from . import views

# url configuration
urlpatterns = [
 path('upload/', views.upload, name='upload')
]