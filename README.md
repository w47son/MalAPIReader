# MalAPIReader
Parses API entries and prints information from the website [MalAPI.io](https://malapi.io/)

## Setup
Clone the repo:
```
$ git clone https://github.com/w47son/MalAPIReader.git && cd MalAPIReader
```

Run the script:
```
$ python3 MalAPIReader.py -h
```
## Usage
``` 
usage: MalApiReader [-h] [-s STRINGS] [-p PE] [-b] [-r] [--update]

Read information from MalAPI.io for WinAPI information.

optional arguments:
  -h, --help            show this help message and exit
  -s STRINGS, --strings STRINGS
                        Specify the STRINGS to read. The WinAPI will be checked against MalAPI and information will be printed about the API.
  -p PE, --pe PE        Specify the PE to read. The WinAPI will be checked against MalAPI and information will be printed about the API.
  -b, --bitcoin         Find bitcoin addresses in STRINGS.
  -r, --report          Write report to the reports directory
  --update              Look for new WinApi from MalAPI to update the database.
```
  

## Thanks
Thank you HuskyHacks for your awesome course of Malware Analysis.
