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

def selenium_firefox_SingleTextFile(textfilepath, iterationsPerTextFile, websiteOfInterstScanTime, mediaFolder, csvExportName):
 amountOfIterations = iterationsPerTextFile 
 websitesFile = open(textfilepath, 'r')
 websites = websitesFile.readlines()
 driver = scannerHelper.getSeleniumFireFoxDriver()

 for websiteOfInterest in websites:
   scannerHelper.iterateThroughPage(amountOfIterations, driver, websiteOfInterest, websiteOfInterstScanTime)

 driver.quit()  

 websiteOfInterestSummary = csvExportName+"_Summary"+".csv"
 websiteOfInterestOuput = csvExportName+"_Output"+".csv"
 # create the summary of the traffic for the website of interest
 createCSV.createSummaryCSV(websiteOfInterestSummary, mediaFolder + "/", amountOfIterations)
 createCSV.createOutputCSV(websiteOfInterestOuput, mediaFolder + "/")
 ServersEncounteredInSession.objects.all().delete()        