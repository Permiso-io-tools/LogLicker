import LogModules

if __name__ == "__main__":
    #getting args from parser
    args: dict = LogModules.data_load.load_args()
    
    #formatting args for kwarg function call
    loadFilesArgs: dict = {
      "exrexFile": args.get("exrexFilePath"),
      "regexFile": args.get("regexFilePath"),
      "manifestFile": args.get("inputManifestFilePath"),
      "stringList": args.get("stringList")
    }
    
    #grabbing inputed dictionaries from files
    exrexDict: dict | None
    regexDict: dict | None
    manifest: dict | None
    exrexDict, regexDict, manifest = LogModules.data_load.load_files(**loadFilesArgs)
    deAnonymize: bool = args.get("deAnonymize")
    regexList: list = args.get("regexList")
    
    #writing whatever's requested to file
    manifest = LogModules.data_search.modify_manager(
      args["inputCase"], 
      args["inputData"], 
      regexDict,
      exrexDict, 
      manifest, 
      args["outputFilePath"],
      deAnonymize,
      regexList
    )
    
    #setting up args    
    writeArgs: dict = {
      "manifest": manifest,
      "manifestFilePath": args.get("outputManifestFilePath")
    }
    
    
    if "outputManifestFilePath" in args:
        writeArgs["manifestFilePath"] = args["outputManifestFilePath"]
    
    LogModules.write(**writeArgs)
    
