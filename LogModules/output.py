import json
import hashlib
import os

def write_manifest(manifest: dict, manifestFilePath: str | None = None):
    #writes manifest to output manifest file path
    if manifestFilePath:
        dir_name = os.path.dirname(manifestFilePath)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        with open(manifestFilePath, "w") as manifestFile:
            manifestFile.write(json.dumps(manifest, indent = 4))

def hash_file_content_from_path(inputData, chunk_size: int = 4096) -> str | None:
    #provides file hash for consistent and groupable output
    md5 = hashlib.md5()
    try:
        with open(inputData, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except FileNotFoundError:
        print(f"Error: File {inputData} not found.")
    except PermissionError:
        print(f"Error: No permission to read the file {inputData}.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return None

def get_unique_filename(outputPath, dataPath) -> tuple[str, str] | list:
    #provides unique output file name using generated hash
    if not dataPath:
        print("Error: dataPath not provided.")
        return []

    outputFilePath: str = outputPath
    outputFilePathFile, outputFilePathExt = os.path.splitext(outputFilePath)

    if dataPath:
        dataHash: str = hash_file_content_from_path(dataPath)

    if dataHash:
        return [f'{outputFilePathFile}-{dataHash}{outputFilePathExt}', dataHash]

    return []

def get_manifest_filename(outputPath, dataHash) -> str:
    #provides unique manifest file name using generated hash
    outputFilePath: str = outputPath
    outputFilePathFile, outputFilePathExt = os.path.splitext(outputFilePath)

    return f'{outputFilePathFile}-{dataHash}{outputFilePathExt}'