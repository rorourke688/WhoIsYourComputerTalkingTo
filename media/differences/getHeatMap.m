function [websiteTable] = getHeatMap(category, testingNames, controlFiles)

firstTestingFileName = string(category) + '/'+ string(testingNames(1)) + '/' + string(controlFiles(1));
websiteTable = readtable(firstTestingFileName, detectImportOptions(firstTestingFileName));

for j=2:length(controlFiles)
    filePath = string(category) + '/'+ string(testingNames(1)) + '/' + string(controlFiles(j));
    tableToAdd = readtable(filePath, detectImportOptions(filePath));
    websiteTable = vertcat(websiteTable, tableToAdd);   
end

websiteTable = groupsummary(websiteTable,'ORG','sum');
websiteTable= removevars(websiteTable,{'GroupCount'});

name = 'website';
s = repelem(testingNames(1), height(websiteTable));
websiteTable.(name) = s';

for i=2:length(testingNames)
    fileName = string(category) + '/'+ string(testingNames(i)) + '/' + string(controlFiles(1));
    tableOne = readtable(fileName, detectImportOptions(fileName));

    for j=2:length(controlFiles)
        filePath = string(category) + '/'+ string(testingNames(i)) + '/' + string(controlFiles(j));
        table2 = readtable(filePath, detectImportOptions(filePath));
        tableOne = vertcat(tableOne, table2);   
    end
    
    groupSumaryTable = groupsummary(tableOne,'ORG','sum');
    groupSumaryTable= removevars(groupSumaryTable,{'GroupCount'});
    name = 'website';
    s = repelem(testingNames(i), height(groupSumaryTable));
    groupSumaryTable.(name) = s';
    % at this point table one has all the tables one after the other, now
    % we cmpress the table

    websiteTable = vertcat(websiteTable, groupSumaryTable); 

end

end