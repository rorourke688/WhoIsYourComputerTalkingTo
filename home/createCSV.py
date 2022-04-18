from .ViewsRequest import ServerEncounterSummary, MalicousServers, TrafficEncountered
import csv

IN_BOTH = 'In Both'
IN_OTHER = 'Occured In Other'
IN_BASE = 'Occured In Base'

TOWARDS_OTHER = 'Other'
TOWARDS_BASE = 'Base'
TOWARDS_EITHER = 'Either'

def createSummaryCSV(fileName, location, numberOfIterations):
 csvFile = open(location + str(fileName), 'w', newline='')
 writer = csv.writer(csvFile)
 writer.writerow(['occurrences_mean', 'occurrences_std', 'bytes_mean', 'bytes_std', 'server_mean', 'server_std', 'bytes_co_var', 'occurrences_co_var', 'server_co_var', 'org', 'occurPerServer'])
 summary = ServerEncounterSummary.getSummaryOfSession(numberOfIterations)

 for row in summary:
    writer.writerow([row['occurrences_mean'], row['occurrences_std'], row['bytes_mean'], row['bytes_std'], row['server_mean'], row['server_std'], row['bytes_co_var'], row['occurrences_co_var'], row['server_co_var'], row['org'], row['occurencePerServer']])

 csvFile.close()

def createOutputCSV(fileName, location):
  csvFile = open(str(location) + str(fileName), 'w', newline='')
  writer = csv.writer(csvFile)
  writer.writerow(['ORG', 'IP', 'COUNTRY', 'CITY', 'OCCURENCES', 'LAT', 'LONG'])

  for row in TrafficEncountered.getTrafficList():
    writer.writerow([row['org'], row['ip'], row['country'], row['city'], row['occurrences'], row['latitude'], row['longitude']])

  csvFile.close()

def createDifferenceBetweenSummaryCSV_AFTER(filenameInludingPATH, onlyInFile2Array):
  csvFile = open(filenameInludingPATH, 'w', newline='')
  writer = csv.writer(csvFile)
  writer.writerow(['ORG', 'OCCURENCE'])

  for row in onlyInFile2Array:
    writer.writerow([row['org'], row['occurrences_mean']])  

  csvFile.close()  

def createDifferenceBetweenSummaryCSV_BOTH(filenameInludingPATH, bothDifferenceArray):
  csvFile = open(filenameInludingPATH, 'w', newline='')
  writer = csv.writer(csvFile)
  writer.writerow(['ORG', 'OCCURENCE'])

  for row in bothDifferenceArray:
    writer.writerow([row['org'], row['differenceInOccurenceMean']])  

  csvFile.close() 

def appendOtherTrafficOutput(output, otherDic):
  for otherCase in otherDic:
    occuredInFile = False
    for o in output:
      if o['IP'] == otherCase['IP']:
        occuredInFile = True

    if occuredInFile == False:
      outputDifference1 = {
        'ORG': otherCase['ORG'], 
        'IP': otherCase['IP'],
        'COUNTRY': otherCase['COUNTRY'],
        'CITY': otherCase['CITY'],
        'LAT': otherCase['LAT'],
        'LONG': otherCase['LONG'],
        'OCCURENCE_DIFFERENCE': -100.0,
        'favoured': IN_OTHER,
        'towards': TOWARDS_OTHER
      }

      output.append(outputDifference1)   

def getServerOutputWhenThereIsCrossOver(baseDic, otherDic):
  output = []
  for baseRow in baseDic:
      occuredInBase = True
      occuredInOther = False
      baseHolder = int(baseRow['OCCURENCES'])
      base_Occur = baseHolder

      if baseHolder == 0 :
        baseHolder = 1
        occuredInBase = False

      other_Occur = 0 

      for otherRow in otherDic:
        if baseRow['IP'] == otherRow['IP']:
          other_Occur = int(otherRow['OCCURENCES'])
          occuredInOther = True
    
      percentageDifference = 100 * (base_Occur - other_Occur) / baseHolder

      favoured = IN_BOTH
      toward = TOWARDS_BASE

      if occuredInBase == False and occuredInOther :
        favoured = IN_OTHER

      if occuredInBase and occuredInOther == False:
        favoured = IN_BASE

      if favoured == IN_BOTH and percentageDifference < 0:
        toward = TOWARDS_OTHER

      if favoured == IN_BOTH and percentageDifference == 0:
           favoured = IN_BOTH
           toward =  TOWARDS_EITHER 


      outputDifference = {
       'ORG': baseRow['ORG'], 
       'IP': baseRow['IP'],
       'COUNTRY': baseRow['COUNTRY'],
       'CITY': baseRow['CITY'],
       'LAT': baseRow['LAT'],
       'LONG': baseRow['LONG'],
       'OCCURENCE_DIFFERENCE': percentageDifference,
       'favoured': favoured,
       'towards': toward
      }      

      output.append(outputDifference)

  return output


def getSummaryBothAndOne(fileOneDic, fileTwoDic, outputBoth, outputFileOne):
      for firstFile in fileOneDic:
        
        orgOne = firstFile['org']
        bothShareOrg = False

        for secondFile in fileTwoDic:
          orgTwo = secondFile['org']

          if orgOne == orgTwo:
            occurPerServer1 = float(firstFile['occurrences_mean'])
            occurPerServer2 = float(secondFile['occurrences_mean']) 
            bothShareOrg = True

            outputDifference1 = {
              'org': orgOne, 
              'fileOneOccurrences_mean': occurPerServer1,
              'fileTwoOccurrences_mean': occurPerServer2,
              'differenceInOccurenceMean': round(occurPerServer2 - occurPerServer1)
            }

            outputBoth.append(outputDifference1)

        if bothShareOrg == False:
          occurPerServerFile1 = float(firstFile['occurrences_mean'])
            
          outputDifference2 = {
            'org': orgOne, 
            'occurrences_mean': occurPerServerFile1,
            'fileNumber': 1
          }

          outputFileOne.append(outputDifference2)

def getSummaryInSecondFile(fileTwoDic, outputBoth, outputFileTwo):
    for row in fileTwoDic:
      orgfileTwo = row['org']
      sharedOrg = False

      for bothIn in outputBoth:
        if orgfileTwo == bothIn['org']:
          sharedOrg = True

      if sharedOrg == False:
          occurMeanFile2 = float(row['occurrences_mean'])
          outputDifference2 = {
            'org': orgfileTwo, 
            'occurrences_mean': occurMeanFile2,
            'fileNumber': 2
          }

          outputFileTwo.append(outputDifference2)          



