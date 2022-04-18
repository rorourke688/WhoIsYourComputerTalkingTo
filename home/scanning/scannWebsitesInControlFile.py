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
from .helper import scannerHelper

packet_counts = Counter()

# control proccess for the website of interest.
# there is an iteration of control sites. ie google and bing.
# go through google to obtain traffic, save a csv file as before.csv
# go to the website of interest followed by the control site again. Note the differences
def goThroughControlProcessForWebsite(controlSites, contorlFileIteration, controlFileTimePerpage, mediaFolder, websiteName, amountOfIterations, websiteOfInterest, websiteOfInterstScanTime):
  
  for site in controlSites:
    controlName = scannerHelper.getFileName(site)
    driver = scannerHelper.getSeleniumFireFoxDriver()
    printsOfWebsites = 1

    # first go through control before website of interest
    scannerHelper.iterateThroughPage(contorlFileIteration, driver, site, controlFileTimePerpage)
    controlSummaryBefore = controlName +"Before.csv"
    # create the before summary for the control site traffic
    createCSV.createSummaryCSV(controlSummaryBefore, mediaFolder + "/"+websiteName+"/control/Before/", amountOfIterations)
    ServersEncounteredInSession.objects.all().delete()

    # now we want to explore the site of interest to see its affect on the control traffic obtained next
    # we only create this csv file once
    scannerHelper.iterateThroughPage(amountOfIterations, driver, websiteOfInterest, websiteOfInterstScanTime)
    
    if printsOfWebsites == 0:
     websiteOfInterestSummary = websiteName+".csv"
     # create the summary of the traffic for the website of interst
     createCSV.createSummaryCSV(websiteOfInterestSummary, mediaFolder + "/"+websiteName + "/", amountOfIterations)
     printsOfWebsites = printsOfWebsites + 1

    ServersEncounteredInSession.objects.all().delete() 

    # first go through control before website of interest
    scannerHelper.iterateThroughPage(contorlFileIteration, driver, site, controlFileTimePerpage)
    controlSummaryAfter = controlName +"_After.csv"
    # create the before summary for the control site traffic
    createCSV.createSummaryCSV(controlSummaryAfter, mediaFolder + "/" + websiteName + "/control/After/", amountOfIterations)
    ServersEncounteredInSession.objects.all().delete()
    driver.quit()


# Main Method of this class
# Purpose: Go through control website - one site in test website - back to control sites
# see the effect of going to the contorl sites on the captured traffic
def selenium_firefox_CookieTest(textfilepath, iterationsPerTextFile, websiteOfInterstScanTime, textFileName, mediaFolder, controlFile):
 contorlFileIteration = 2
 controlFileTimePerpage = 5
 amountOfIterations = iterationsPerTextFile 

 websitesFile = open(textfilepath, 'r')
 websites = websitesFile.readlines()

 controlFile = open(controlFile, 'r')
 controlSites = controlFile.readlines()

 for websiteOfInterest in websites:
  websiteName = scannerHelper.getFileName(websiteOfInterest)

  goThroughControlProcessForWebsite(controlSites, contorlFileIteration, controlFileTimePerpage, mediaFolder, websiteName, amountOfIterations, websiteOfInterest, websiteOfInterstScanTime)

  



   
