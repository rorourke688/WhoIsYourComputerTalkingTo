from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, request
from .scanning.helper import scannerHelper

from home import CompareSummary
from .models import Server, NetworkTraffic, ServersEncounteredInSession, ServerDifference, SummaryDifferenceBoth, SummaryDifferenceNotInBoth
from . import scan, createCSV

from .ViewsRequest import ServerEncounterSummary, MalicousServers, TrafficEncountered
import csv
from django.conf import settings
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import HttpResponse
from selenium import webdriver
from selenium.webdriver import ChromeOptions
import os
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from .scanning import scannWebsitesInControlFile, scanOneSetOfSites

IN_BOTH = 'In Both'
IN_OTHER = 'Occured In Other'
IN_BASE = 'Occured In Base'

TOWARDS_OTHER = 'Other'
TOWARDS_BASE = 'Base'
TOWARDS_EITHER = 'Either'

# first is iteration and second is timing
def getIterationsAndTiming(textFileName):
  numberFile = open(textFileName, 'r')
  keyNumbers = numberFile.readlines()
  numbers = []
  for number in keyNumbers:
    numbers.append(number)

  return numbers    


def getNewServerTraffic(request):  
  trafficList = TrafficEncountered.getTrafficList()
  return JsonResponse({"servers": trafficList})

def getNewServerTrafficMalicous(request):  
  maliciousServerList = MalicousServers.getMaliciousServersList()
  return JsonResponse({"servers":maliciousServerList}) 

# this method is called when we want to initiate the scanning process
def scanWebsitesControl(request):
  # gets the file of interest and the two numbers needed for execution
  numbers = getIterationsAndTiming('text/keyNumbers.txt')
  numberOfIterations = int(numbers[0])
  timePerPage = int(numbers[1])

  textFileName = str(request.headers.get('fileName'))
  testFilePath = 'text/websites/'+ textFileName + '.txt'

  controlFilePath = 'text/websites/control.txt'
  mediaFolderPath = settings.MEDIA_ROOT + "/" + textFileName
  individualControlPath =  mediaFolderPath + "/individualControl"  

  scannWebsitesInControlFile.selenium_firefox_CookieTest(testFilePath, numberOfIterations, timePerPage, textFileName, individualControlPath, controlFilePath)
  
  return HttpResponse('Scanning Complete')

# this method is called when we want to initiate the scanning process
def scanWebsitesInSingleFile(request):
  numbers = getIterationsAndTiming('text/keyNumbers.txt')
  numberOfIterations = int(numbers[0])
  timePerPage = int(numbers[1])

  textFileName = str(request.headers.get('fileName'))
  csvExportName = str(request.headers.get('csvName'))
  testFilePath = 'text/websites/'+ textFileName + '.txt'
  mediaFolderPath = settings.MEDIA_ROOT + "/" + textFileName

  scanOneSetOfSites.selenium_firefox_SingleTextFile(testFilePath, numberOfIterations, timePerPage, mediaFolderPath, csvExportName)
  
  return HttpResponse('Scanning Complete') 


def getOrgNameInfo(request):
  numbers = getIterationsAndTiming('text/keyNumbers.txt')
  numberOfIterations = int(numbers[0])
  summary = ServerEncounterSummary.getSummaryOfSession(numberOfIterations)
  return JsonResponse({"servers": summary})   

def deleteAllRowsInNetworkTraffic(request):
  ServersEncounteredInSession.objects.all().delete()
  return HttpResponse('Network Traffic Deleted from database')

# upload method for the summary csv file
@csrf_exempt
def uploadSummary(request):
  if request.method == 'POST':
    uploaded_File_Base_Case = request.FILES['file1']
    uploaded_File_Other_Case = request.FILES['file2']

    textFileName = str(request.headers.get('fileName'))
    filename =  str(uploaded_File_Other_Case.name).replace('After','')  

    base_caseReader = csv.DictReader(uploaded_File_Base_Case.read().decode('utf-8').splitlines())
    other_caseReader = csv.DictReader(uploaded_File_Other_Case.read().decode('utf-8').splitlines())

    fileOneDic = []
    fileTwoDic = []

    bothShare = []
    onlyInFile1 = []
    onlyInFile2 = []
    
    for bRow in base_caseReader:
      fileOneDic.append(bRow)

    for oRow in other_caseReader:
      fileTwoDic.append(oRow)

    createCSV.getSummaryBothAndOne(fileOneDic, fileTwoDic, bothShare, onlyInFile1)
    createCSV.getSummaryInSecondFile(fileTwoDic, bothShare, onlyInFile2)

    BOTH_PATH = settings.MEDIA_ROOT+"/"+textFileName+ "_BOTH" + ".csv"
    NOT_BOTH_PATH = settings.MEDIA_ROOT+"/"+textFileName+ "_UNIQUE" + ".csv"

    createCSV.createDifferenceBetweenSummaryCSV_AFTER(NOT_BOTH_PATH, onlyInFile2)
    createCSV.createDifferenceBetweenSummaryCSV_BOTH(BOTH_PATH, bothShare)
    
    SummaryDifferenceBoth.objects.all().delete()
    SummaryDifferenceNotInBoth.objects.all().delete()

    for bothItems in bothShare:
      SummaryDifferenceBoth.objects.create(org=bothItems['org'], fileOneOccurrences_mean=bothItems['fileOneOccurrences_mean'], fileTwoOccurrences_mean=bothItems['fileTwoOccurrences_mean'], differenceInOccurenceMean=bothItems['differenceInOccurenceMean']) 
    
    for notBothItems in onlyInFile1:
      SummaryDifferenceNotInBoth.objects.create(org=notBothItems['org'], occurrences_mean=float(notBothItems['occurrences_mean']), fileNumber=int(notBothItems['fileNumber']))

    for notBothItems in onlyInFile2:
      SummaryDifferenceNotInBoth.objects.create(org=notBothItems['org'], occurrences_mean=float(notBothItems['occurrences_mean']), fileNumber=int(notBothItems['fileNumber']))  
      
  return HttpResponse('done')

# upload method for the ouput csv file
@csrf_exempt
def upload(request):
  if request.method == 'POST':
    uploaded_File_Base_Case = request.FILES['file1']
    uploaded_File_Other_Case = request.FILES['file2']

    base_caseReader = csv.DictReader(uploaded_File_Base_Case.read().decode('utf-8').splitlines())
    other_caseReader = csv.DictReader(uploaded_File_Other_Case.read().decode('utf-8').splitlines())

    baseDic = []
    otherDic = []
    
    for bRow in base_caseReader:
      baseDic.append(bRow)

    for oRow in other_caseReader:
      otherDic.append(oRow)

    output = createCSV.getServerOutputWhenThereIsCrossOver(baseDic, otherDic)
    createCSV.appendOtherTrafficOutput(output, otherDic)

  ServerDifference.objects.all().delete()
   #save in db the call   
  for items in output:
    ServerDifference.objects.create(ip_address=items['IP'], country=items['COUNTRY'], city=items['CITY'], latitude=items['LAT'], longitude=items['LONG'], org=items['ORG'], occurenceDifference=items['OCCURENCE_DIFFERENCE'], favoured=items['favoured'], towards=items['towards'])
      
  return HttpResponse('done')

def getServerDifferences(request):
  return JsonResponse({"servers": list(ServerDifference.objects.all().values())})

def getServerDifferencesSummary(request):
  TotalNumber = 0
  TotalInOther = 0
  TotalInBase = 0
  TotalinBoth = 0
  TotalInBothFavourOther = 0
  TotalInBothFavourBase = 0
  TotalInBothSame = 0

  listOfAllServerDifferences = list(ServerDifference.objects.all().values())

  for row in listOfAllServerDifferences:
    TotalNumber = TotalNumber + 1

    if row['favoured'] == IN_BASE:
      TotalInBase = TotalInBase + 1

    if row['favoured'] == IN_OTHER:
      TotalInOther = TotalInOther + 1

    if row['favoured'] == IN_BOTH:
      TotalinBoth = TotalinBoth + 1

      if row['towards'] == TOWARDS_BASE:
        TotalInBothFavourBase = TotalInBothFavourBase + 1

      if row['towards'] == TOWARDS_OTHER:
        TotalInBothFavourOther = TotalInBothFavourOther + 1

      if row['towards'] == TOWARDS_EITHER:
        TotalInBothSame = TotalInBothSame + 1  

  outputDifference = {
    'TotalOther': round(100*(TotalInOther / TotalNumber), 2),
    'TotalBase': round(100*(TotalInBase / TotalNumber), 2),
    'TotalInBoth': round(100*(TotalinBoth / TotalNumber), 2),
    'TotalInBothOther': round(100*(TotalInBothFavourOther / TotalinBoth), 2),
    'TotalInBothBase': round(100*(TotalInBothFavourBase / TotalinBoth), 2),
    'TotalInBothSame': round(100*(TotalInBothSame / TotalinBoth), 2)
  }

  dic = [] 
  dic.append(outputDifference)             
  return JsonResponse({"servers": dic})

def getSummaryInBoth(request):  
  trafficList = CompareSummary.getSummaryOrgsInBoth()
  return JsonResponse({"servers": trafficList})

def getSummaryInFile(number):
  return CompareSummary.getSummaryOrgsInFile(number)

def getSummaryInFileOne(request):
  trafficList = getSummaryInFile(1)
  return JsonResponse({"servers": trafficList})

def getSummaryInFileTwo(request):
  trafficList = getSummaryInFile(2)
  return JsonResponse({"servers": trafficList})

def getListOfNames(path):
  websitesFile = open(path, 'r')
  websites = websitesFile.readlines()
  websiteNames = []

  for website in websites:
      websiteNames.append(scannWebsitesInControlFile.getFileName(website))

  websitesFile.close()
  return websiteNames

def getArrayOfContent(path):
  array = []
  with open(path,'r') as file:
    content=csv.DictReader(file.read().splitlines())
    for row in content:
      array.append(row)  

  return array    


@csrf_exempt
def outputAllSummaryFiles(request):
  if request.method == 'POST':
    textFileOfInterest = request.headers.get('fileName')
    pathToControlFile = 'text/websites/control.txt'
    pathToTextFileOfWebsiteNames = 'text/websites/'+ textFileOfInterest + '.txt'
    pathToFolder = settings.MEDIA_ROOT + "/" + textFileOfInterest + "/individualControl/"

    websiteNames = getListOfNames(pathToTextFileOfWebsiteNames)
    controlNames = getListOfNames(pathToControlFile)

    for web in websiteNames:
      pathToControl = pathToFolder + web + "/control/"
      
      # each website name has a file for each control file
      for control in controlNames:
        beforePATH = pathToControl + "Before/" + control + "Before.csv"
        afterPATH = pathToControl + "After/" + control + "_After.csv"

        before = getArrayOfContent(beforePATH)
        after = getArrayOfContent(afterPATH)
        # now we have access to all the content of all the before and after cases.
        bothShare = []
        onlyInFile1 = []
        onlyInFile2 = []

        createCSV.getSummaryBothAndOne(before, after, bothShare, onlyInFile1)
        createCSV.getSummaryInSecondFile(after, bothShare, onlyInFile2)

        createCSV.createDifferenceBetweenSummaryCSV_AFTER(settings.MEDIA_ROOT+"/differences/AFTER/"+web+"/"+control+".csv", onlyInFile2)
        createCSV.createDifferenceBetweenSummaryCSV_BOTH(settings.MEDIA_ROOT+"/differences/BOTH/"+web+"/"+control+".csv", bothShare)



  return HttpResponse('done')
