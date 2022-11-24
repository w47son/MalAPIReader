import requests
import bs4
import argparse
import sys
from pathlib import Path
from datetime import datetime
import pefile
from hashlib import sha256
import json


parser = argparse.ArgumentParser(prog = 'MalApiReader',formatter_class=argparse.RawDescriptionHelpFormatter,
                                description = '''Read information from MalAPI.io for WinAPI information.''')
parser.add_argument('-s', "--strings",type=argparse.FileType('r'),
                    help="Specify the STRINGS to read. The WinAPI will be checked against MalAPI and information will be "
                         "printed about the API.") 
parser.add_argument('-p', "--pe",
                    help="Specify the PE to read. The WinAPI will be checked against MalAPI and information will be "
                         "printed about the API.")
parser.add_argument("-b", "--bitcoin", help="Find bitcoin addresses in STRINGS.", action="store_true")
parser.add_argument("-r", "--report", help="Write report to the reports directory", action="store_true") 
parser.add_argument("--update",help="Look for new WinApi from MalAPI to update the database.", action="store_true")
args = parser.parse_args()


if len(sys.argv) == 1:
    parser.print_help()
    parser.exit()

# Globals
current_time = datetime.now()


if args.report and (args.pe or args.strings):
    class Logger(object):
        def __init__(self):
            self.terminal = sys.stdout
            sampleName=args.strings.name if args.strings.name else args.pe
            self.log = open("reports/" +sampleName+"_"+ str(datetime.now().strftime("%Y-%m-%d-%H-%M")) + "_report.log", "a")

        def write(self, message):
            self.terminal.write(message)
            self.log.write(message)

        def flush(self):
            pass

    sys.stdout = Logger()



def update(databaseDict=''):
    try:
        APICheck = requests.get("https://malapi.io/")
        soup = bs4.BeautifulSoup(APICheck.text, 'html.parser')
        htmltable = soup.find('table', { 'id' : 'main-table' })
        list_table = tableDataText(htmltable)

        if databaseDict: #If args.update
            isUpdated=False
            for i in range(len(list_table[1:])):
                for a in list_table[1+i]:
                    if a not in databaseDict[list_table[0][i]]:
                        try:
                            isUpdated=True
                            APICheck = requests.get("https://malapi.io/winapi/"+a)
                            APICheck.raise_for_status()
                            APISoup = bs4.BeautifulSoup(APICheck.text, 'html.parser')
                            details = APISoup.select('.detail-container .content')
                            ApiInfo = details[1].getText().strip().replace('\n','').replace('\r','')
                            databaseDict[list_table[0][i]][a]=ApiInfo
                            print(list_table[0][i],':',a,'updated')
                        except Exception as e:
                            print(e)
            if not isUpdated:
                print("No new API to update")

            databaseDict = json.dumps(databaseDict)
            databaseFile=open("storage/malApiDatabase.json","w")
            databaseFile.write(databaseDict)
            databaseFile.close()
        else: #Else create database
            createDatabase(list_table)
            return True
    except Exception as e:
        print(e)
        return False


def tableDataText(table):    
    def rowgetDataText(tr, coltag):        
        return [td.get_text(strip=True) for td in tr.find_all(coltag)]  
    rows = []
    
    trs = table.find_all('tr')
    tableData=table.find_all('table')
    headerow = rowgetDataText(trs[0], 'th')
    rows.append(headerow)
    for table in tableData: 
        listrow=rowgetDataText(table, 'td')
        rows.append(listrow)
    return rows


def createDatabase(list_table): #Creates a database if doesnt exist
    databaseDict={}

    for i in list_table[0]:
        databaseDict[i]={}
    keys=list(databaseDict.keys())

    lengthTable=len(list_table[1:])
    for i,name in enumerate(list_table[1:]):
        lenghtNames=len(name)
        print("\n")
        print(keys[i])
        print(str(i+1)+"/"+str(lengthTable))
        print("\n")
        countNames=0
        for j in name:
            try:
                APICheck = requests.get("https://malapi.io/winapi/"+j)
                APICheck.raise_for_status()
                APISoup = bs4.BeautifulSoup(APICheck.text, 'html.parser')
                details = APISoup.select('.detail-container .content')
                ApiInfo = details[1].getText().strip().replace('\n','').replace('\r','')

                databaseDict[keys[i]][j]=ApiInfo

                countNames=countNames+1
                print(str(countNames)+"/"+str(lenghtNames))
                
            except Exception as e:
                print(e)

    databaseDict = json.dumps(databaseDict)
    databaseFile=open("storage/malApiDatabase.json","w")
    databaseFile.write(databaseDict)
    databaseFile.close()


def compareStrings(databaseDict): # compare stringsFile and database
    compareFile=args.strings.read().split('\n')

    for i in databaseDict:
        isPrinted=False
        for a in compareFile:
            if a in databaseDict[i]:
                if not isPrinted:
                    print("\n")
                    print(i,"type of API")
                    isPrinted=True
                print(a)
                print("    \\\\---> ",databaseDict[i][a])
        if not isPrinted:
            print("\n")
            print("No API found for",i)
    
    if args.bitcoin:
        findBitcoinWallet(compareFile)
            

def findBitcoinWallet(compareFile):
    digits58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    def decode_base58(bc, length):
        n = 0
        for char in bc:
         n = n * 58 + digits58.index(char)
        return n.to_bytes(length, 'big')
    def check_bc(bc):
        try:
            bcbytes = decode_base58(bc, 25)
            return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
        except Exception:
            return False

    print("\n")
    bitcoinFound=False
    for s in compareFile:
        if check_bc(s):
            if not bitcoinFound:
                print("-" * 15 + "BitcoinAddress" + "-" * 15)
                bitcoinFound=True
            print(s)
    if not bitcoinFound:
        print("NO bitcoin addresses found")
    



def pefilecheck(databaseDict):
    try:
        pe = pefile.PE(args.pe, fast_load=True)
    except Exception as e:
        print("Unable to parse file. May not be a PE.")
        print("Full error: {}".format(str(e)))
        quit()
    pe.parse_data_directories()
    try:
        for i in databaseDict:
            isPrinted=False
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    try:
                        imp_name = imp.name.decode("utf-8").strip()
                        if imp_name in databaseDict[i]:
                            if not isPrinted:
                                print("\n")
                                print(i,"type of API")
                                isPrinted=True
                            print(imp_name)
                            print("    \\\\---> ",databaseDict[i][imp_name])
                    except:
                        continue
            if not isPrinted:
                print("\n")
                print("No API found for",i)
    except KeyboardInterrupt:
        pass

def openDatabase():
    database=open("storage/malApiDatabase.json","r")
    databaseString=database.read()
    database.close()

    databaseDict=json.loads(databaseString)
    return databaseDict
    

def main():
    Storage = Path("storage/malApiDatabase.json")
    if Storage.exists():
        print("-" * 15 + "MalAPIReader.py" + "-" * 15)
        malAPIDictionary = openDatabase()
        print("Current time: {}".format(current_time))
        
        if args.update: #Update the current database
            print("\n")
            print("Updating...")
            update(malAPIDictionary)
        
        if args.pe:
            print("Sample name: {}".format(args.pe))
            pefilecheck(malAPIDictionary)
        elif args.strings:
            print("Sample name: {}".format(args.strings.name))
            compareStrings(malAPIDictionary)
        
    else:
        print("No database found. Creating a new one...")
        if update():
            print("Database created!")
            main()


if __name__ == "__main__":
    main()
