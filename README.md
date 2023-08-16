# LogLicker
Tool for obfuscating and deobfuscating data. This tool is built to be highly customizable, so while it does have in-built support for AWS CloudTrail logs, support for other data types can be added. This is because this tool searches and replaces sensitive data based on regexes pulled from an inputted file.

## Required Packages
>```bash
>python3 -m pip install regex boto3 exrex
>```

## Input

This tool offers a CLI (Command Line Interface). As such, here we review its use:

Note the following commands examples do not specify a file path for RunLogLicker.py which will need to be included or a symlink should be registered:
>**MAC**
>```bash
>ln -s /path/to/file/RunLogLicker.py RunLogLicker.py
>```
>-----
>**Windows**
>```bash
>mklink RunLogLicker.py C:\path\to\file\RunLogLicker.py
>```

The tool has different subparsers for different inputs. Calling the three different subparsers looks like this:
>```PowerShell
>python3 RunLogLicker.py rawtext
>python3 RunLogLicker.py cloudtrail
>python3 RunLogLicker.py rawcloudtrail
>```
>-----
>**While this documentation goes over the available arguments for each subparser, the following commands will show them while using the tool.**
>```PowerShell
>python3 RunLogLicker.py rawtext -h
>python3 RunLogLicker.py cloudtrail -h
>python3 RunLogLicker.py rawcloudtrail -h
>```
-----
>**For all subparsers, if no output file is specified then the output will be written to the location of the RunLogLicker folder within the >output directory.**
-----
### cloudtrail - Subparser

Inbuilt support for the CloudTrail API to pull logs directly from CloudTrail.

>--awsaccesskey, --awssecretkey, --region
>- These are the arguments needed to create a CloudTrail Client. They are not required if environmental variables for configured.
>```PowerShell
>python3 RunLogLicker.py cloudtrail --awsaccesskey ________ --awssecretkey ________ --region us-west-2
>```
>-----
>.--eventid, --eventname, --readonly, --username, --resourcetype, --resourcename, --eventsource, --accesskeyid
>- These are the mutually exclusive arguments for grabbing CloudTrail logs (only one can be used at a time). Logs that do not fit the argument provided are not retrieved from CloudTrail. https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/lookup_events.html
>```PowerShell
>python3 RunLogLicker.py cloudtrail --readonly true
>```
>-----
>--starttime, --endtime
>-  These are the non-mutually exclusive arguments for grabbing CloudTrail logs, which means as many of these can be added as wanted. An example call using these looks like:
>```PowerShell
>python3 RunLogLicker.py cloudtrail --starttime 07132023 --endtime 07152023 
>```
### rawtext - Subparser

Pull from a text file.
**For the best performance, each line should hold an entire object, instead of each object being accross multiple lines. As the tool grabs and writes line-by-line.**

>--inputfilepath
>- The path to the file to grab data from
>```PowerShell
>python3 RunLogLicker.py rawtext --inputfilepath input/example/file.txt
>python3 RunLogLicker.py rawtext --ifp input/example/file.txt
>```
>-----
>--deanonymize or -da (true)
>- Whether or not to deobfustcate data. (Requires input that needs de-anonymized and the manifest that says how to de-anonymize.)
>```PowerShell
>python3 RunLogLicker.py rawtext --inputfilepath input/example/file.txt -imfp output/manifest.json -da true
>```

### rawtext & cloudtrail arguments

The rawtext and cloudtrail subparsers also have the following common arguments:

>--exrexfilepath, --regexfilepath
>- The path to the regexes and exrexes. Regexes are regular expressions used to find data, and exrexes are the regular expressions used to generate a random string. By default >these go to default/default_exrex.json and default/default_regex.json. These should be JSON files formatted as such:
>```json
>{
>    "longTermAccessKeyID": "(?:AKIA)[A-Z0-9]{16}",
>    "shortTermAccessKeyID": "(?:ASIA)[A-Z0-9]{16}",
>    "publicKeyID": "(?:APKA)[A-Z0-9]{16}",
>    "ipv4": "((?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|>[0-1]?[0-9]{1,2}))(?![0-9]))"
>}
>```
>-----
>--inputmanifestfilepath, --outputmanifestfilepath
>- The input manifest must be provided when deanonymizing, so the program can know what values where replaced and what to put them back to. The input manifest can be provided when >anonymizing which will replace values with the same value in the manifest. This allows for keeping consistant replacements accross multiple files, and for custom replacement of >specific values. The output manifest file path designates where the manifest of changed values is outputted to.
>```PowerShell
>python3 RunLogLicker.py cloudtrail --inputmanifestfilepath input/example/manifest.json --outputmanifestfilepath output/example/manifest.json
>```
>-----
>--limit
>- The max amount of logs to grab from the cloudtrail API, by default the value is 1000.
>```PowerShell
>python3 RunLogLicker.py cloudtrail --inputmanifestfilepath input/example/manifest.json --outputmanifestfilepath output/example/manifest.json --limit 50
>```
>-----
>--regexlist
>- To only get specific values to anonymize, you can specify here. Only the values provided will be anonymized, assuming the corresponding regexes already exist in the regex file.
>```PowerShell
>python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -rl ipv4 arn
>```

### rawcloudtrail

The rawcloudtrail subparser allows for direct dumping of CloudTrail logs without any modifications. The arguments are the same as the cloudtrail parser, without any of the ones overlapping arguments that exist for cloudtrail and rawtext.

### rawcloudtrail, cloudtrail and rawtext arguments

The only overlapping argument for all of the above is:
>--outputfilepath
>- The path where the output file is put. If no output file path is put nothing will be written. This can be useful for just finding possible >sensitive information within logs, without wanting to anonymize it, as a manifest can still be created if a file path for the manifest is >configured.
>```PowerShell
>python3 RunLogLicker.py rawcloudtrail --outputfilepath output/example/rawcloudtrail.txt
>python3 RunLogLicker.py rawcloudtrail --ofp output/example/rawcloudtrail.txt
>python3 RunLogLicker.py rawcloudtrail
>```

## Subparser Examples
```PowerShell
python3 RunLogLicker.py rawcloudtrail -es ssm.amazonaws.com -s 2021-12-01 -r us-west-2 -ofp output/rawcloudtrail.txt -l 20
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-07-19 -r us-west-2 -ofp output/rawcloudtrail.txt
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-07-19 -r us-west-2 -ofp output/rawcloudtrail.txt
python3 RunLogLicker.py rawcloudtrail -s 2021-12-01 -e 2023-08-01 -r us-west-2 -ofp output/rawcloudtrail.txt -l 20000
```
-----
```PowerShell
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true
python3 RunLogLicker.py rawtext -ifp output/rawcloudtrail.txt -ofp output/anonymizedrawtext.txt -rl ipv4 arn shortTermAccessKeyID
python3 RunLogLicker.py rawtext -ifp output/anonymizedrawtext.txt -ofp output/deanonymizedrawtext.txt -imfp output/manifest.json -da true
```
-----
```PowerShell
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -es ssm.amazonaws.com -s 2021-12-01 -l 20
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-07-19
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-07-19 -rl ipv4 arn
python3 RunLogLicker.py cloudtrail -ofp output/anonymizedcloudtrail.txt -imfp output/manifest.json -s 2021-12-01 -e 2023-08-01 -l 20000
```
-----
## Example Call Chain
#### The following example was chosen to take a raw cloudtrail log, anonymize it and get the manifest, use both to reverse back to de-anonymized version.
```PowerShell
----------
Get non-anonymized raw cloudtrail data.
----------

python3 RunLogLicker.py rawcloudtrail

  88      dP.Yb   dPEEb8 88     88  dPTTb8 77  dP 867888 88<>Yb
  AA     EE   Yb dP      88     88 dP      88edP  88__   88__dP
  88  DD Yb   dP Yb  X88 88     88 Yb      99mYb  88""   88VYb
  88ooBB  Yb.dP   YboodP 88ood8 88  YbZZdP 88  Yb 882283 88  Yb

[*] Parsing input arguments.
[*] Loading regex files and any specified manifest.
[*] Processing.
[*] Fetching data.
[*] Completed. - 5bf42d01fbe2bb83df9ed5b8597fc48e

----------
Anonymize the raw cloudtrail data.
----------

python3 RunLogLicker.py rawtext -ifp /Users/UserA/Repos/LogLicker/output/rawCTOutput-5bf42d01fbe2bb83df9ed5b8597fc48e.json

  88      dP.Yb   dPEEb8 88     88  dPTTb8 77  dP 867888 88<>Yb
  AA     EE   Yb dP      88     88 dP      88edP  88__   88__dP
  88  DD Yb   dP Yb  X88 88     88 Yb      99mYb  88""   88VYb
  88ooBB  Yb.dP   YboodP 88ood8 88  YbZZdP 88  Yb 882283 88  Yb

[*] Parsing input arguments.
[*] Loading regex files and any specified manifest.
[*] Processing.
[*] Anonymizing - Writing to output & manifest.
[*] Completed. - f146979ecec0448282f24803c93bafdd

----------
Use anonymized data file and manifest to search the anonymized data and replace with orginals.
----------

python3 RunLogLicker.py rawtext -ifp /Users/UserA/Repos/LogLicker/output/anonymizedRawtext-f146979ecec0448282f24803c93bafdd.json -imfp /Users/UserA/Repos/LogLicker/output/manifest-f146979ecec0448282f24803c93bafdd.json -da true

  88      dP.Yb   dPEEb8 88     88  dPTTb8 77  dP 867888 88<>Yb
  AA     EE   Yb dP      88     88 dP      88edP  88__   88__dP
  88  DD Yb   dP Yb  X88 88     88 Yb      99mYb  88""   88VYb
  88ooBB  Yb.dP   YboodP 88ood8 88  YbZZdP 88  Yb 882283 88  Yb

[*] Parsing input arguments.
[*] Loading regex files and any specified manifest.
[*] Processing.
[*] De-anonymizing - Writing to output.
[*] Completed. - f146979ecec0448282f24803c93bafdd
```
-----
## Output

The two outputs of the tool are a text file containing the transformed data, as well as the manifest of those transformations. The orginal file or deanonymized file can also be obtained as output. The manifest is formatted as such:

Note the below manifest is the result of double anonymization through the tool.

```JSON
{
    "longTermAccessKeyID": {},
    "shortTermAccessKeyID": {
        "ASIA44BFS3DB9AZSLVKN": "ASIARRA7214EQQRGSOR8",
        "ASIA58XS6QR4LQUU6MAT": "ASIAQNG9PSO77X5XE6XJ",
        "ASIAKESN7KC3TQNRUUD7": "ASIALG1VFSHW4T3QIOI9",
        "ASIA7IMFF7TTJ6GGK5RK": "ASIA69KD9OFYVKE9WNCO",
        "ASIAEM0Q7HMERFGZHVX1": "ASIA20VIIH15A2HZ3YQK",
        "ASIAWPC2Z9LK2AIEOKSU": "ASIALR275EU6OCEOD4DZ",
        "ASIALCJDZ7KLQZ280X44": "ASIAH30ULGUKKLXWNXMY",
        "ASIA3HOROPQ12T83EXL2": "ASIANDXL666WMBUHKWSK",
        "ASIAJLP0YUGS7Y9J1L5W": "ASIAFKUY82ZLMDQWN9JW",
    },
    "publicKeyID": {},
    "stsServiceBearerTokenID": {},
    "contextSpecificCredentialID": {},
    "groupID": {},
    "ec2InstanceProfileID": {},
    "iamUserID": {},
    "managedPolicyID": {},
    "roleID": {
        "AROAX8FPY6SLINGD5TRIY": "AROAFMMNPSOMSUB3U0PS7",
        "AROAHF19VBSC3PEQ5S7AR": "AROAXTDOSUSGP0DYHQIZP",
        "AROA72BM0TPC9EOJDGRSS": "AROAOKOZ9RAV91QYNLKSJ",
        "AROAESH5Z6ZNASDBVB35Z": "AROAXYIJM34DYM4LCCZ5I"
    },
    "certificateID": {},
    "accountID": {
        "037004843194": "335218083019"
    },
    "username": {
        "random-namex0cmjcGZFzcB": "random-nameKr9MbbOGlggB",
        "random-generated-nameKEV833qWlntN": "random-nameWdE6hgKCByqw",
        "random-generatedNlTKfrplXYd9": "random-names4PWayd1paxS",
        "random-namerkIM3rcQqCrG": "random-generated5714THlzRgiz"
    },
    "arn": {
        "assumed-role/random-namex0cmjcGZFzcB/permisoIdentity": "random-generated-name25VkjCitbTAl",
        "role/random-namex0cmjcGZFzcB": "random-userP05GjxuUtlqG",
        "random-userqfqIsrqkbeXE": "random-userqEre8a1P0d2v",
        "random-nameBfffGInqmkoC": "random-userJNa22tvcOPEF",
        "assumed-role/random-generated-nameKEV833qWlntN/LascoEntropy-3308480586824857098": "random-user0OFxJmCUrcY2",
        "random-userBhz6XEm4Iq5d": "random-nameOHzall3NlDrP",
        "random-namer9M8cK8JAZnq": "random-generated-userrI5pGvVoSsrk",
        "assumed-role/random-generated-nameKEV833qWlntN/MandoService5411494363614758860": "random-userAcg538doYyur",
    },
    "instanceID": {},
    "ipv4": {
        "210.200.250.217": "17.76.253.255",
        "251.255.239.248": "4.210.254.11"
    },
    "region": {
        "eu-northwest-3": "ap-isob-south-2r"
    },
    "email": {},
    "specifiedStrings": {}
}
```
