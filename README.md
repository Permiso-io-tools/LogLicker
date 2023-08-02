# LogLicker
Tool for obfuscating and deobfuscating data. This tool is built to be highly customizable, so while it does have in-built support for AWS CloudTrail logs, support for other data types can be added. This is because this tool searches and replaces sensitive data based on regexes pulled from an inputted file.  

### Input

This program is a CLI (Command Line Interface) based program. As such, a call to it looks like this:  

```PowerShell
python3 RunLogLicker.py
```

The program has different subparsers for different inputs. Calling the three different subparsers looks like this:  
```PowerShell
python3 RunLogLicker.py rawtext
python3 RunLogLicker.py cloudtrail
python3 RunLogLicker.py rawcloudtrail
```
##### Cloudtrail

This program has inbuilt support for the CloudTrail API, and can pull logs directly from CloudTrail.  

--awsaccesskey, --awssecretkey, --region
- These are the arguments needed to create a CloudTrail Client. These are not required if environmental variables for these are configured. An example call using these would look like: 
```PowerShell
python3 RunLogLicker.py cloudtrail --awsaccesskey ________ --awssecretkey ________ --region us-west-2
```
  
--eventid, --eventname, --readonly, --username, --resourcetype, --resourcename, --eventsource, --accesskeyid
- These are the mutually exclusive arguments for grabbing CloudTrail logs, meaning that only one can be provided in a call. Logs that do not fit the argument provided are not grabbed from CloudTrail
```
python3 RunLogLicker.py --readonly true
```
  
--starttime, --endtime, --eventcategory
-  These are the non-mutually exclusive arguments for grabbing CloudTrail logs, which means as many of these can be added as wanted. An example call using these looks like:
```PowerShell
ptyhon3 RunLogLicker.py cloudtrail --starttime 07132023 --endtime 07152023 --eventcategory management
```
  
##### rawtext

This tool can also pull from a text file. For the best performance, each line should hold an entire object, instead of each object being accross multiple lines. As the tool grabs and writes line-by-line. 

--inputfilepath
- The path to the file to grab data from  
```PowerShell
python3 RunLogLicker.py rawtext --inputfilepath input/example/file.txt
```
  
--deanonymize
- Whether or not to deobfustcate data. 

##### rawtext & cloudtrail arguments

THe rawtext and cloudtrail subparser have common arguments. These arguments are:  

--exrexfilepath, --regexfilepath
- The path to the regexes and exrexes. Regexes are regular expressions used to find data, and exrexes are the regular expressions used to generate a random string. By default these go to default/default_exrex.json and default/default_regex.json. These should be JSON files formatted as such: 
```JSON
{
    "longTermAccessKeyID": "(?:AKIA)[A-Z0-9]{16}", 
    "shortTermAccessKeyID": "(?:ASIA)[A-Z0-9]{16}",
    "publicKeyID": "(?:APKA)[A-Z0-9]{16}",
    "ipv4": "((?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9]))"
}
```
  
--inputmanifestfilepath, --outputmanifestfilepath  
- The input manifest must be provided when deanonymizing, so the program can know what values where replaced and what to put them back to. The input manifest can be provided when anonymizing which will replace values with the same value in the manifest. This allows for keeping consistant replacements accross multiple files, and for custom replacement of specific values. The output manifest file path designates where the manifest of changed values is outputted to. 
  
```PowerShell
python3 RunLogLicker.py cloudtrail --inputmanifestfilepath input/example/manifest.json --outputmanifestfilepath output/example/manifest.json
```
  
--limit  
- The max amount of logs to grab from the cloudtrail API, by default the value is 1000.
```PowerShell
python3 RunLogLicker.py cloudtrail --inputmanifestfilepath input/example/manifest.json --outputmanifestfilepath output/example/manifest.json --limit 50
```

--regexlist
- To only get specific values to anonymize, you can specify here. Only the values provided will be anonymized, assuming the corresponding regexes already exist in the regex file. 
```PowerShell
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -rl ipv4 arn
```


##### rawcloudtrail
  
The rawcloudtrail subparser allows for direct dumping of CloudTrail logs without any modifications. The arguments are the same as the cloudtrail parser, without any of the ones overlapping between cloudtrail and rawtext. 

##### rawcloudtrail, cloudtrail and rawtext arguments
  
The only overlapping argument for all of the above is:  
--outputfilepath
- The path where the output file is put. If no output file path is put nothing will be written. This can be useful for just finding possible sensitive information within logs, without wanting to anonymize it, as a manifest can still be created if a file path for the manifest is configured.  
```PowerShell
python3 rawcloudtrail --outputfilepath output/example/rawcloudtrail.txt
```  

##### FULL EXAMPLE CALLS  
```PowerShell
python3 RunLogLicker.py rawcloudtrail -es ssm.amazonaws.com -s 2021-12-01 -r us-west-2 -ofp output/rawcloudtrail.txt -l 20 
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt  
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -es ssm.amazonaws.com -s 2021-12-01 -l 20
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true  
```
```PowerShell
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-07-19 -r us-west-2 -ofp output/rawcloudtrail.txt  
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt  
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-07-19  
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true    
```
```PowerShell
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-07-19 -r us-west-2 -ofp output/rawcloudtrail.txt  
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt -rl ipv4 arn shortTermAccessKeyID  
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-07-19 -rl ipv4 arn shortTermAccessKeyID  
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true  
```
```PowerShell
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-08-01 -r us-west-2 -ofp output/rawcloudtrail.txt -l 20000
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt -sl "mfaAuthenticated"
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-08-01 -l 20000
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true    
```
### Output

The two outputs of this program are a text file containing the transformed data, as well as the manifest of those transformations. The manifest is formatted as such:

```JSON
{
    "longTermAccessKeyID": {
    },
    "shortTermAccessKeyID": {
        "ASIA5TT5ZDOC5LO8ELH5": "ASIA7SBRHABGNYFYQMB9",
        "ASIA5TT335123NVJRB5Z": "ASIAKAZU53U5554HIC0O",
        "ASIA5TT5ZDOC123Z5I17": "ASIAGLD30G29PEKSB5XU",
        "ASIA5TT5ZDOC5M53RI5Q": "ASIAHH26U7O871OH2QNY",
        "ASIA5TT5ZD12354R126T": "ASIA3S1AL1LAR731EQPL",
        "ASIA5TT5ZDOC5G71555O": "ASIAXHFW1YU1YNMR0RWT",
        "ASIA5TT5ZDOCWRWS55T3": "ASIAKJ03ZWF2BONELQG8",
        "ASIA5TT5ZDO5555EDCJ7": "ASIAF1UD5LP9YYTPBEJU",
        "ASIA5TT5ZDOCU55WFGOA": "ASIA7W90N0QT3QGH6TTR",
        "ASIA5TT5ZDOC3T55IUFT": "ASIAF2ANL2I27XXV4UZV",
        "ASIA5T123123555C7Y6G": "ASIAGB4LCFHF4UFCCVEA",
        "ASIA5TT5ZDOC2EJ55542": "ASIAG1DX4HAR6S55RNAA",
        "ASIA5TT5ZDO15C55WPHP": "ASIA6POY2OKUHP7MFI71",
        "ASIA5TT5ZDOCZ5NIZ555": "ASIAXUHT3UWPMRUVPVFJ",
        "ASIA5TT5Z235CV355IC5": "ASIA0F08MI8KK0SN6LON",
        "ASIA5TT5ZDOC355IFH1M": "ASIANU2LKTT1H7FP9LA9",
        "ASIA5TT5ZDOC55YUIWW5": "ASIAIZBO8FGLG8KDPA93",
        "ASIA5TT5ZDOCZ45555PX": "ASIACZFI6MDBKMQ83I4H",
        "ASIA5TT55DQ4A555I5CK": "ASIAZ61ESZXF5I4H7M55",
        "ASIA5TT5ZDOC455YRG7B": "ASIAKEX7PA2CRDZLBWW1",
        "ASIA5TT5ZDOCZUS55OPA": "ASIA1MGEPZTHWW808156",
        "ASIA5TT5ZDO521T55WRH": "ASIACBV84RBD09U43SEG",
        "ASIA5TT5ZDOC3W255X26": "ASIA3W3ENLYPCVRBA9G4"
    },
    "publicKeyID": {},
    "stsServiceBearerTokenID": {},
    "contextSpecificCredentialID": {},
    "groupID": {},
    "ec2InstanceProfileID": {},
    "iamUserID": {
        "AIDA5TT5ZD155412GXUGKI": "AIDALQ1YG5Q0T6ZICM0R"
    },
    "managedPolicyID": {},
    "roleID": {
        "AROA5TT5ZDO55N52SZ3K7": "AROAH4ZUZAY98RBXNF60Y",
        "AROA5TT5ZDO5512EYYMN6": "AROAEWKAD33NGT0HOG75B",
        "AROA5TT554O55FIBBO532": "AROAY830MQVXJ2GPY9V8C"
    },
    "certificateID": {},
    "accountID": {},
    "arn": {
        "channel/aws-service-channel/inspector2/123-5323-47c6-ab86-feb0355ef281": "random-userRDCT1roiAQ09",
        "assumed-role/AWSServiceRoleForAmazonInspector2/inspector123551657873886114": "random-userPB3FRe0UrBo1",
        "assumed-role/AWSServiceRoleForAmazonInspector2/inspector1235815536633363518": "random-generated-userhNtoVUOqUy7u",
        "assumed-role/AWSServiceRoleForAmazonInspector2/LambdaStateController123655716519979093": "random-generated-nameJ5xCpNQSrhHJ",
        "assumed-role/AWSServiceRoleForAmazonInspector2/LambdaStateController12320554655481433": "random-userFzJfxgwsoTDv"
    },
    "instanceID": {},
    "ipv4": {
        "121.211.220.210": "36.1.216.207",
        "123.222.201.92": "4.202.187.05",
        "114.0.0.1": "054.253.253.037"
    }
}
```

If no output file path is provided, only a manifest will be given.