from LogModules import data_load, data_search, write_manifest, get_manifest_filename

asciiImage: str = '''
  88      dP.Yb   dPEEb8 88     88  dPTTb8 77  dP 867888 88<>Yb
  AA     EE   Yb dP      88     88 dP      88edP  88__   88__dP
  88  DD Yb   dP Yb  X88 88     88 Yb      99mYb  88""   88VYb
  88ooBB  Yb.dP   YboodP 88ood8 88  YbZZdP 88  Yb 882283 88  Yb
'''

if __name__ == "__main__":
    print(asciiImage)

    args: dict = data_load.load_args()

    loadFilesArgs: dict = {
      "exrexFile": args.get("exrexFilePath"),
      "regexFile": args.get("regexFilePath"),
      "manifestFile": args.get("inputManifestFilePath"),
      "stringList": args.get("stringList")
    }

    #load and verify manifest/regexes
    exrexDict, regexDict, manifest = data_load.load_files(**loadFilesArgs)
    deAnonymize: bool = args.get("deAnonymize")
    regexList: list = args.get("regexList")

    #write details to file
    manifest, dataHash = data_search.modify_manager(
      args.get("inputCase"),
      args.get("inputData"),
      regexDict,
      exrexDict,
      manifest,
      args.get("outputFilePath"),
      deAnonymize,
      regexList
    )

    #rewrite manifest file name with hash
    if dataHash and args.get("outputManifestFilePath"):
        updateManifestFilePath = get_manifest_filename(args.get("outputManifestFilePath"), dataHash)
        if updateManifestFilePath:
            args['outputManifestFilePath'] = updateManifestFilePath

    writeArgs: dict = {
      "manifest": manifest,
      "manifestFilePath": args.get("outputManifestFilePath")
    }

    write_manifest(**writeArgs)

    print(f'[*] Completed. - {dataHash}')
