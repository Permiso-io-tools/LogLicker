import json
import boto3
import argparse
import regex as re
import random
import string

def load_args() -> dict:
    # Arguments
    parser = argparse.ArgumentParser(description="Anonymize logs")

    ##different input types
    subparsers = parser.add_subparsers(help='sub-command help', dest = "type")

    ##cloudtrail api
    cloudTrail = subparsers.add_parser('cloudtrail')
    cloudTrail.add_argument("-aak", "--awsaccesskey", required=False)
    cloudTrail.add_argument("-ask", "--awssecretkey", required=False)
    cloudTrail.add_argument('-r', "--region" , type=str, required=False)
    cloudTrail.add_argument("-ec", "--eventcategory")

    ##request parameters of get logs, can only use one
    requestParameters = cloudTrail.add_mutually_exclusive_group()
    requestParameters.add_argument("-eid", '--eventid', type=str)
    requestParameters.add_argument("-en", '--eventname', type=str)
    requestParameters.add_argument("-ro", '--readonly', type=str)
    requestParameters.add_argument("-un", '--username', type=str)
    requestParameters.add_argument("-rt", '--resourcetype', type=str)
    requestParameters.add_argument("-rn", '--resourcename', type=str)
    requestParameters.add_argument("-es", '--eventsource', type=str)
    requestParameters.add_argument("-akid", '--accesskeyid', type=str)

    cloudTrail.add_argument("-s", "--starttime")
    cloudTrail.add_argument("-e", '--endtime')
    cloudTrail.add_argument("-efp", "--exrexfilepath", type=str, default="defaults/default_exrex.json")
    cloudTrail.add_argument("-rfp", "--regexfilepath", type=str, default="defaults/default_regex.json")
    cloudTrail.add_argument("-omfp", "--outputmanifestfilepath", type=str, default="output/manifest.json")
    cloudTrail.add_argument("-imfp", "--inputmanifestfilepath", type=str)
    cloudTrail.add_argument("-ofp", "--outputfilepath", type=str)
    cloudTrail.add_argument("-rl", "--regexlist", nargs="+", type=str, help="list of data types to anonymize", default=[])
    cloudTrail.add_argument("-l", "--limit", type=int, default=1000)
    cloudTrail.add_argument("-sl", "--stringlist",type=str, action="append", help="list of strings to remove", default=[])

    ##raw text input
    rawText = subparsers.add_parser('rawtext')
    rawText.add_argument('-ifp', "--inputfilepath", type=str, required = True)
    rawText.add_argument("-efp", "--exrexfilepath", type=str, default="defaults/default_exrex.json")
    rawText.add_argument("-rfp", "--regexfilepath", type=str, default="defaults/default_regex.json")
    rawText.add_argument("-omfp", "--outputmanifestfilepath", type=str, default="output/manifest.json")
    rawText.add_argument("-imfp", "--inputmanifestfilepath", type=str)
    rawText.add_argument("-ofp", "--outputfilepath", type=str)
    rawText.add_argument("-da", "--deanonymize", type=bool, default=False)
    rawText.add_argument("-rl", "--regexlist", nargs="+", type=str, help="list of data types to anonymize", default=[])
    rawText.add_argument("-sl", "--stringlist",type=str, action="append", help="list of strings to remove", default=[])

    #also cloudtrail api, just grabbing logs
    rawCloudTrail = subparsers.add_parser('rawcloudtrail')
    rawCloudTrail.add_argument("-aak", "--awsaccesskey")
    rawCloudTrail.add_argument("-ask", "--awssecretkey")
    rawCloudTrail.add_argument('-r', "--region" , type=str)
    rawCloudTrail.add_argument("-ec", "--eventcategory")

    ##request parameters of get logs, can use one
    requestParameters = rawCloudTrail.add_mutually_exclusive_group()
    requestParameters.add_argument("-eid", '--eventid', type=str)
    requestParameters.add_argument("-en", '--eventname', type=str)
    requestParameters.add_argument("-ro", '--readonly', type=str)
    requestParameters.add_argument("-un", '--username', type=str)
    requestParameters.add_argument("-rt", '--resourcetype', type=str)
    requestParameters.add_argument("-rn", '--resourcename', type=str)
    requestParameters.add_argument("-es", '--eventsource', type=str)
    requestParameters.add_argument("-akid", '--accesskeyid', type=str)

    rawCloudTrail.add_argument("-s", "--starttime")
    rawCloudTrail.add_argument("-e", '--endtime')
    rawCloudTrail.add_argument("-ofp", "--outputfilepath", type=str, required = True)
    rawCloudTrail.add_argument("-l", "--limit", type=int, default=1000)
    
    args = parser.parse_args()
    
    returnValue = {}
    
    setInputCase = parser.parse_args().type   
    if setInputCase != "rawcloudtrail":
        returnValue["inputManifestFilePath"] = getattr(args, "inputmanifestfilepath")
        returnValue["outputManifestFilePath"] = getattr(args, "outputmanifestfilepath")
        returnValue["exrexFilePath"] = getattr(args, "exrexfilepath")
        returnValue["regexFilePath"] = getattr(args, "regexfilepath")
        returnValue["regexList"] = getattr(args, "regexlist")
        returnValue["stringList"] = getattr(args, "stringlist")
    returnValue["outputFilePath"] = getattr(args, "outputfilepath")

    match setInputCase:
    ##assign values if cloudtrail subparse was chosen
        case "cloudtrail" | "rawcloudtrail":
            clientCreationDict: dict = {}
            
            clientCreationDict["aws_access_key_id"] = getattr(args, "awsaccesskey") 
            clientCreationDict["aws_secret_access_key"] = getattr(args, "awssecretkey")
            clientCreationDict["region_name"] = getattr(args, "region")
            
            setStartTime: str | None = getattr(args, "starttime")
            setEndTime: str | None = getattr(args, "endtime")
            setEventCategory: str | None = getattr(args, "eventcategory")
            
            ##checks which parameter was chosen
            setParameter = None
            if(args.eventid):
                setParameter = {"EventId": args.eventid}
            elif(args.readonly):
                setParameter = {"ReadOnly": args.readonly}
            elif(args.username):
                setParameter = {"Username": args.username}
            elif(args.resourcetype):
                setParameter = {"ResourceType": args.resourcetype}
            elif(args.resourcename):
                setParameter = {"ResourceName": args.resourcename}
            elif(args.eventsource):
                setParameter = {"EventSource": args.eventsource}
            elif(args.accesskeyid):
                setParameter = {"AccessKeyId": args.accesskeyid}
            
            ##creating paginator
            clientCT = boto3.client('cloudtrail', **clientCreationDict)
            paginator = clientCT.get_paginator('lookup_events')
            cloudTrailQuery = {}
            
            if(setParameter): 
                cloudTrailQuery["LookupAttributes"] = [
                            {
                                'AttributeKey': list(setParameter.items())[0][0],
                                'AttributeValue': list(setParameter.items())[0][1]
                            },
                        ]
            if(setStartTime):
                setStartTime = re.sub(r':| |, ', '-', setStartTime)
                cloudTrailQuery["StartTime"] = setStartTime
            if(setEndTime):
                setEndTime = re.sub(r':| |, ', '-', setEndTime)
                cloudTrailQuery["EndTime"] = setEndTime
            if(setEventCategory):
                cloudTrailQuery["EventCategory"] = setEventCategory
            cloudTrailQuery["PaginationConfig"] = {
                    'MaxItems': args.limit,
                    'PageSize': args.limit,
                    }
            
            setInputData = paginator.paginate(**cloudTrailQuery)

        case "rawtext":
            
            setInputData = args.inputfilepath
            returnValue["deAnonymize"] = getattr(args, "deanonymize")
    
    if returnValue.get("regexList") == None:
        returnValue["regexList"] = []
    if returnValue.get("stringList") == None:
        returnValue["stringList"] = []
    returnValue["inputData"] = setInputData
    returnValue["inputCase"] = setInputCase
    
    return(returnValue)

def load_files(exrexFile: str | None = None, regexFile: str | None = None, manifestFile: str | None = None, stringList: str | None = None) -> tuple:

    regexDict: dict = {}
    exrexDict: dict = {}
    manifest: dict = {}
    
    #file for how to find data
    if regexFile is not None:
        try:
            with open(regexFile, "r") as rawRegex:
                regexDict = json.load(rawRegex)
            if len(regexDict) == 0:
                print("Warning! No regex's found.")
        except Exception as error:
            print("ERROR OCCURED DURING REGEX LOAD")
            print(error)
        
    #file for how to replace data
    if exrexFile is not None:
        try:
            with open(exrexFile, "r") as rawExrex:
                exrexDict: dict = json.load(rawExrex)
        except Exception as error:
            print("ERROR OCCURED DURING EXREX LOAD")
            print(error)
        
    if manifestFile is not None:
        try:
            with open(manifestFile, "r") as rawManifest:
                manifest: dict = json.load(rawManifest)
        except Exception as error:
            print("ERROR OCCURED DURING MANIFEST LOAD: ")
            print(error)
    
    #See if regex / exrex are correct
    for key in list(regexDict.keys()):
        if key not in exrexDict:
            exrexDict[key] = regexDict[key]
            print("Warning! Not every Regex has an Exrex. Using the Regex as an Exrex, but this may cause invalid randomization.")
        if key not in manifest:
            #formatting manifest
            manifest[key] = {}
            
    #adding user specified strings to manifest for replacement 
    if not manifest.get("specifiedStrings"):
        manifest["specifiedStrings"] = {}
    for item in stringList:
        if item not in manifest["specifiedStrings"]:
            randomString = ''.join(random.choice(string.digits + string.digits + string.ascii_letters + string.ascii_letters + string.punctuation) for i in range(20))
            manifest["specifiedStrings"][item] = re.sub(r"\\", r"", randomString)
            
    return(exrexDict, regexDict, manifest)