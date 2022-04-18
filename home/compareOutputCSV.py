from .ViewsRequest import ServerEncounterSummary, MalicousServers, TrafficEncountered
import csv

def getSummaryBothAndOne(fileOneDic, fileTwoDic, outputBoth, outputFileOne):
      for firstFile in fileOneDic:
        
        orgOne = firstFile['ORG']
        bothShareOrg = False

        for secondFile in fileTwoDic:
          orgTwo = secondFile['ORG']

          if orgOne == orgTwo:
            occurPerServer1 = float(firstFile['OCCURENCES'])
            occurPerServer2 = float(secondFile['OCCURENCES']) 
            bothShareOrg = True

            outputDifference1 = {
              'org': orgOne, 
              'fileOneOccurrences_mean': occurPerServer1,
              'fileTwoOccurrences_mean': occurPerServer2,
              'differenceInOccurenceMean': round(occurPerServer2 - occurPerServer1)
            }

            outputBoth.append(outputDifference1)

        if bothShareOrg == False:
          occurPerServerFile1 = float(firstFile['OCCURENCES'])
            
          outputDifference2 = {
            'org': orgOne, 
            'occurrences_mean': occurPerServerFile1,
            'fileNumber': 1
          }

          outputFileOne.append(outputDifference2)

def getSummaryInSecondFile(fileTwoDic, outputBoth, outputFileTwo):
    for row in fileTwoDic:
      orgfileTwo = row['ORG']
      sharedOrg = False

      for bothIn in outputBoth:
        if orgfileTwo == bothIn['ORG']:
          sharedOrg = True

      if sharedOrg == False:
          occurMeanFile2 = float(row['OCCURENCES'])
          outputDifference2 = {
            'org': orgfileTwo, 
            'occurrences_mean': occurMeanFile2,
            'fileNumber': 2
          }

          outputFileTwo.append(outputDifference2)   