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

The `--strings` option takes one argument: the path of the strings file. It will compare the strings and check for any WinApi. If an entry is found, information is then printed.

i.e.
![strings](https://user-images.githubusercontent.com/54062322/203841778-d974c684-54d4-4b2b-86d4-d418e826fc79.png)


The `--pe` option takes one argument: the path and name to an PE file. It will then read the Import Address Table and check for any WinApi. If an entry is found, information is then printed.

i.e.
![pefile](https://user-images.githubusercontent.com/54062322/203842000-35965867-b137-4aff-895e-ea18c5fe7299.png)


The `--bitcoin` option finds bitcoin addresses with the `--strings` flag

i.e.
![bitcoin1](https://user-images.githubusercontent.com/54062322/203842732-abae0f45-59e9-4067-a2a8-f38ba957474c.png)
![bitcoin2](https://user-images.githubusercontent.com/54062322/203842746-aed7b0d4-5350-4096-8f5d-662d45fbb12a.png)


The `--update` looks for new WinApi from MalApi to update the database.

i.e.
![update](https://user-images.githubusercontent.com/54062322/203842183-63bc058a-7ee9-42d9-91d4-24fba019579a.png)

The `--report` option writes the console to a file with file name, timestamped log in `reports/` for later retrieval.


## Thanks
Thank you HuskyHacks for your awesome Malware Analysis course.
