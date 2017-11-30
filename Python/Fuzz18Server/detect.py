import xmltodict
import re

def check_sqlinjecttion_error(dbms,html):
    regexList = []
    errorList =[]
    htmlLower = html.lower()
    #  load errors regex from file to a list
    with open("sqlerrors.xml") as f:
        regexXmlDict = xmltodict.parse(f)
        if dbms == None:
            for regexDbms, regexOfDbmsList in regexXmlDict["errors"].iteritems():
                regexList.extend(regexOfDbmsList["regexp"])
        else:
            regexList = regexXmlDict["errors"][dbms]
    if re.search(r"SQL (warning|error|syntax)", html, re.I):
        errorList.append("SQL errors")
    for regex in regexList:
        if re.search(regex, html, re.I):
            errorList.append(regex)
    # if errorList == []:
    #     for regex in regexList:
    #         keywords = re.findall("\w+", re.sub(r"\\.", " ", regex))
    #         for keyword in keywords:
    #             if keyword.lower() in htmlLower:
    #                 errorList.append(keyword)
    return errorList