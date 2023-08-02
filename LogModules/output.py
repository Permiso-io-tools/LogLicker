import json

def write(manifest: dict, manifestFilePath: str | None = None):
    #writes manifest to output manifest file path
    if manifestFilePath:
        with open(manifestFilePath, "w") as manifestFile:
            manifestFile.write(json.dumps(manifest, indent = 4))