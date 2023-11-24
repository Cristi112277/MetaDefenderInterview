import hashlib
import json
import requests
import time
import sys

filename = ''
apiKey = ''
url = 'https://api.metadefender.com/v4/'


def GetFileHash():
    try:
        with open(filename,"rb") as f:
            bytes = f.read() 
            fileHash = hashlib.sha256(bytes).hexdigest()
            return fileHash
    except FileNotFoundError:
        print("File not found, exiting...")
        exit()

def VerifyHashExistence(fileHash):
    print("Verify hash existence in cache")
    headers = {'apikey': apiKey}
    x = requests.get('{url}/hash/{fileHash}'.format(fileHash=fileHash, url=url), headers=headers) 
    if x.status_code == 404:
        print("Hash was not found")
        return False
    elif x.status_code == 200:
        print("Hash found")
        return x.json()
    elif x.status_code == 401:
        print("Wrong api key, exiting...")
    else:
        print("There was a problem reaching the MetaDefender servers")
        return None

def UploadFile():
    print("Start file upload")
    headers = {'apikey': apiKey,
           'Content-Type': 'application/octet-stream','filename': 'test.txt'}
    x = requests.post('https://api.metadefender.com/v4/file', headers=headers,data=open(filename,"rb"))
    if x.status_code == 200:
        return x.json()["data_id"]

def WaitForResult(dataId):
    tryNumber = 1
    print("Polling every 10 seconds for upload result")
    headers = {'apikey': apiKey,
           'Content-Type': 'application/octet-stream','filename': 'test.txt'}
    print("Polling retry number: {tryNumber}".format(tryNumber=tryNumber))
    response = requests.get('https://api.metadefender.com/v4/file/{dataId}'.format(dataId=dataId), headers=headers,data=open(filename,"rb"))
    while response.json()['process_info']['progress_percentage'] != 100 or tryNumber > 10:
        time.sleep(10)
        tryNumber += 1
        print("Polling retry number: {tryNumber}".format(tryNumber=tryNumber))
        response = requests.get('https://api.metadefender.com/v4/file/{dataId}'.format(dataId=dataId), headers=headers,data=open(filename,"rb"))
    if(tryNumber > 10):
        print("There was a problem retrieving the upload result")
        return False
    print("Succesfully retrieved upload results")
    return response.json()

def PrintResult(jsonResponse):
    print("""
Filename: {}
OverallStatus: {}""".format(jsonResponse["file_info"]["display_name"],jsonResponse["process_info"]["verdicts"][0]))
    for key,value in jsonResponse["scan_results"]["scan_details"].items():
        print("""
Engine: {}
ThreatFound: {}
ScanResult: {}
DefTime: {}
""".format(key,value["threat_found"],value["scan_result_i"],value["def_time"]))


def main():
    fileHash = GetFileHash()
    response = VerifyHashExistence(fileHash)

    if response == False:
        dataId = UploadFile()
        response = WaitForResult(dataId)
        if response == False:
            exit()
    if response == None:
        exit()

    PrintResult(response)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("There was a problem parsing the arguments")
        print("Use: py script.py <file path> <api key>")
        exit()
    filename = sys.argv[1]
    apiKey = sys.argv[2]
    main()




