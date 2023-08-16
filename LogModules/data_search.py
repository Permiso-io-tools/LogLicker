import json
import exrex
import regex as re
import string
import random
import os

from LogModules.output import get_unique_filename

def filter_regexes(regexList: list, regexDict: dict):
    #logic for filtering regexes
    if not regexList:
        return regexDict

    print('[*] Filtering regex list.')
    return {key: value for key, value in regexDict.items() if key in regexList}


def get_all_items(d):
    #only extracts non dict values
    flatDict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            flatDict.update(get_all_items(v))
        else:
            flatDict[k] = v
    return flatDict

def modify_manager(inputCase: str, inputData, regex: dict, exrex: dict, manifest: dict, outputFile: str | None, deAnonymize: str | None, regexList: list) -> tuple[dict , str] | dict:

    print('[*] Processing.')
    dirName = os.path.dirname(outputFile)

    #Logic for getting input data and what function to send it to (de_anonymize or anonymize)
    match inputCase:
        case "cloudtrail":
            #getting the actual logs from the cloudtrail paginator
            if outputFile:
                print('[*] Anonymizing - Writing to output & manifest.')
                if not os.path.exists(dirName):
                    os.makedirs(dirName)
                with open(outputFile, "a") as out:
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

                            manifest = anonymize(jsonString, regex, exrex, manifest, out, regexList, flatManifest)
                            out.write("\n")

        case "rawtext":
            with open(inputData, "r") as inputDataFile:
                if deAnonymize:
                    print('[*] De-anonymizing - Writing to output.')
                    if outputFile:
                        if not os.path.exists(dirName):
                            os.makedirs(dirName)
                        with open(outputFile, "a") as out:
                            for line in inputDataFile:
                                de_anonymize(line, manifest, out)

                else:
                    flatManifest = get_all_items(manifest)
                    if outputFile:
                        if not os.path.exists(dirName):
                            os.makedirs(dirName)
                        print('[*] Anonymizing - Writing to output & manifest.')
                        with open(outputFile, "a") as out:
                            for line in inputDataFile:

                                manifest = anonymize(line, regex, exrex, manifest, out, regexList, flatManifest)


        case "rawcloudtrail":
            print('[*] Fetching data.')
            if not os.path.exists(dirName):
                os.makedirs(dirName)
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

    newOutputFileName, dataHash = get_unique_filename(outputFile, inputData if deAnonymize else outputFile)

    # Rename if needed
    if newOutputFileName and newOutputFileName != outputFile:
        try:
            os.rename(outputFile, newOutputFileName)
            outputFile = newOutputFileName
            return manifest, dataHash
        except OSError as e:
            print(f"Error renaming file: {e}")
            return manifest

def anonymize(jsonString: str, regexDict: dict, exrexDict: dict, manifest: list, outputFile, regexList: list, flatManifest: dict) -> list:

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