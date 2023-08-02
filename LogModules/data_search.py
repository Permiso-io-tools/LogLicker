import json
import exrex
import regex as re
import string
import random

def filter_regexes(regexList: list, regexDict: dict):
    #logic for filtering regexes
    if regexList == []:
        return regexDict
    else:
        return dict(filter(lambda item: item[0] in regexList, regexDict.items()))

def get_all_items(d):
    ##only extracts non dict values
    flatDict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            flatDict.update(get_all_items(v))
        else:
            flatDict[k] = v
    return flatDict

def modify_manager(inputCase: str, inputData, regex: dict, exrex: dict, manifest: dict, outputFile: str | None, deAnonymize: str | None, regexList: list) -> dict: 
    ##Logic for getting input data and what function to send it to (de_anonymize or anonymize)
    match inputCase:
        case "cloudtrail":
            #getting the actual logs from the cloudtrail paginator
            for item in inputData:
                
                eventList: list = item.get("Events", [])
                
                if not eventList:
                    continue
                flatManifest = get_all_items(manifest)
                for event in eventList:
                                
                    jsonString: str = json.dumps(event["CloudTrailEvent"])
                    jsonString = re.sub(r'\\"', '"', jsonString)
                    jsonString = re.sub('\"{', '{', jsonString)
                    jsonString = re.sub('}\"', '}', jsonString)
                    
                    if outputFile:
                        with open(outputFile, "a") as out:
                            
                            manifest = anonymize(jsonString, regex, exrex, manifest, out, regexList, flatManifest)
                            out.write("\n")
                    else:
                        
                            jsonString = jsonString + "\n"
                            manifest = anonymize(jsonString, regex, exrex, manifest, outputFile, regexList, flatManifest)
                                    
        case "rawtext":
            with open(inputData, "r") as inputData:
                if deAnonymize:
                    if outputFile:
                        for line in inputData:
                            with open(outputFile, "a") as out:
                                
                                de_anonymize(line, manifest, out)
                    else:
                        print("Hey! You wanted to de-anonymize the file, but didn't give an output.")
                else:
                    flatManifest = get_all_items(manifest)
                    if outputFile:
                        for line in inputData:
                            with open(outputFile, "a") as out:
                                
                                manifest = anonymize(line, regex, exrex, manifest, out, regexList, flatManifest)
                    else:
                        for line in inputData:
                            
                            manifest = anonymize(line, regex, exrex, manifest, outputFile, regexList, flatManifest)
        case "rawcloudtrail":
            with open(outputFile, "w") as output:
                for item in inputData:
                    
                    eventList: list = item.get("Events", [])
                    
                    if not eventList:
                        continue
                    for event in eventList:
                                        
                        jsonString: str = json.dumps(event["CloudTrailEvent"])
                        jsonString = re.sub(r'\\"', '"', jsonString)
                        jsonString = re.sub('\"{', '{', jsonString)
                        jsonString = re.sub('}\"', '}', jsonString)
                        output.write(jsonString)
                        output.write("\n")
    return manifest
                        
def anonymize(jsonString: str, regexDict: dict, exrexDict: dict, manifest: list, outputFile, regexList: list, flatManifest: dict) -> None:
    ##filters regexes to remove ones not in regexlist
    regexDict = filter_regexes(regexList, regexDict)
    allRegexValuesDict = {}        
    
    #grabs all regex matches
    for dataType, regex in regexDict.items():
        anonymizeValues = re.findall(regex, jsonString)
        
        for item in anonymizeValues:
            allRegexValuesDict[item] = dataType
    
    #sorts matches by length
    allRegexValuesDict = dict(sorted(allRegexValuesDict.items(), key=lambda x:len(x[1]), reverse=True))

    #replaces matched values
    for foundValue, dataType in allRegexValuesDict.items():
        if foundValue not in flatManifest:
            #generates random values based on exrexDict
            randomValue = exrex.getone(exrexDict[dataType], 20)
            count = 0
            
            #fixing overlapping values
            while randomValue in flatManifest.values():
                randomValue = exrex.getone(exrexDict[dataType], 20)
                count = count + 1
                
                if count > 10:
                    randomValue = randomValue + ''.join(random.choice(string.digits) for i in range(5))
            manifest[dataType][foundValue] = randomValue
            flatManifest[foundValue] = randomValue
            
        jsonString = jsonString.replace(foundValue, manifest[dataType][foundValue])
    
    #replacing dictionary values 
    for innerDict in manifest.values():
        for key,value in innerDict.items():
            jsonString = jsonString.replace(key, value)
       
    #writing to output file     
    if outputFile:
        outputFile.write(jsonString)
        
    return manifest
        
def de_anonymize(jsonString: str, manifest: list, outputFile: str | None) -> None:
    #replace all anonymized values with deanonymized value
    for innerDict in manifest.values():
        for key, value in innerDict.items():
            jsonString = jsonString.replace(value, key)
    
    #writes to file
    if outputFile:
        outputFile.write(jsonString)