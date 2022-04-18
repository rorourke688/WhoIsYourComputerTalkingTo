from __future__ import absolute_import, unicode_literals
from tkinter import S

from celery import shared_task
from scapy.all import *
from collections import Counter
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from django.db.models import Max, Q
from home.models import Server, NetworkTraffic, ServersEncounteredInSession, DomainNames
from selenium import webdriver
from selenium.webdriver import ChromeOptions
import os
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from .. import createCSV
from . import scannerHelper

packet_counts = Counter()

def loadControlLogic(prefix, website, controlSites, contorlFileIteration, controlFileTimePerpage, textFileName, mediaFolder, driver, amountOfIterations):
 for site in controlSites:
  controlname = str(site)
  controlname = controlname.replace('/','')
  controlname = controlname.replace('https:','')
  controlname = controlname.replace('.','')

  for i in range(contorlFileIteration):
   driver.get(str(site.strip()))
   capturePackets = sniff(timeout=controlFileTimePerpage)
   scannerHelper.processPackets(capturePackets, i)

  controlOutputOne = textFileName + "CONTROL_OUT_"+prefix+"_"+controlname + "_" + website +".csv"
  controlSummaryOne = textFileName + "CONTROL_SUM_"+prefix+"_"+controlname + "_" + website +".csv"
  createCSV.createOutputCSV(controlOutputOne, mediaFolder + "/output/control" + prefix + "/")
  createCSV.createSummaryCSV(controlSummaryOne, mediaFolder + "/summary/control" + prefix + "/", amountOfIterations)
  ServersEncounteredInSession.objects.all().delete()


def selenium_firefox(textfilepath, iterationsPerTextFile, timeToScan, driver, textFileName, mediaFolder, controlFile):
 contorlFileIteration = 2
 controlFileTimePerpage = 5

 timeToWaitBetweenURls = timeToScan
 amountOfIterations = iterationsPerTextFile

 # for each website in the contol file we test the site x number of times then 
 # we go to the sites in the control file, from this we can see any intersting cross over

 controlFile = open(controlFile, 'r')
 controlSites = controlFile.readlines()
 # Itertate through each cotrol wesbite and take a note of the traffic of each individual website
 loadControlLogic('Before', '',controlSites, contorlFileIteration, controlFileTimePerpage, textFileName, mediaFolder, driver, amountOfIterations)  

 websitesFile = open(textfilepath, 'r')
 websites = websitesFile.readlines()

 for web in websites:
    name = str(web)
    name = name.replace('/','')
    name = name.replace('https:','')
    name = name.replace('.','')

    # testing the website of interest
    filenameForOutput = textFileName + "OUT_"+name+".csv"
    filenameForSummary = textFileName + "SUM_"+name+".csv"

    for i in range(amountOfIterations):
     driver.get(str(web.strip()))
     capturePackets = sniff(timeout=timeToWaitBetweenURls)
     scannerHelper.processPackets(capturePackets, i)
    
    # create the output and summary files for the website of current interest
    createCSV.createOutputCSV(filenameForOutput, mediaFolder + "/output/")
    createCSV.createSummaryCSV(filenameForSummary, mediaFolder + "/summary/", amountOfIterations)
    ServersEncounteredInSession.objects.all().delete()

    # going back to the control to see any change
    loadControlLogic('After', name, controlSites, contorlFileIteration, controlFileTimePerpage, textFileName, mediaFolder, driver, amountOfIterations)  
    driver.close()   
