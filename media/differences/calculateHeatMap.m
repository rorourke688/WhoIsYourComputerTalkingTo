close all;
clear all;


controlFiles = {'amazon.csv', 'awsamazon.csv', 'bing.csv', 'duckduckgo.csv', 'ukindeed.csv', 'youtube.csv', 'google.csv'};
testingNames = {'ebay', 'bbc', 'reddit', 'theguardianuk', 'office', 'ukyahoo', 'netflixgb', 'etsy', 'rightmove', 'govuk', 'paypalukhome', 'trtpilot'};
category = {'cookies/AFTER', 'cookies/BOTH'};
categoryNoCookies = {'AFTER', 'BOTH'};


table_cookiesBoth= getHeatMap(category(2), testingNames, controlFiles);
table_nocookiesBoth= getHeatMap(categoryNoCookies(2), testingNames, controlFiles);

table_cookies_After = getHeatMap(category(1), testingNames, controlFiles);
table_nocookies_After = getHeatMap(categoryNoCookies(1), testingNames, controlFiles);

cookiesOrgOccurence = groupcounts(table_cookies_After, 'website');
nocookiesOrgOccurence = groupcounts(table_nocookies_After, 'website');
websites = string(cookiesOrgOccurence.website);

cookiesOrgGroupCount = cookiesOrgOccurence.GroupCount;
nocookiesOrgGroupCount = nocookiesOrgOccurence.GroupCount;

figure
heatMapAfter = heatmap(table_cookies_After, 'ORG', 'website','ColorVariable','sum_OCCURENCE');
figure
heatMapBoth = heatmap(table_nocookies_After, 'ORG', 'website','ColorVariable','sum_OCCURENCE');
figure
bar = bar(categorical(websites), [cookiesOrgGroupCount, nocookiesOrgGroupCount]);
set(bar, {'DisplayName'}, {'Cookies','No Cookies'}');
legend()





