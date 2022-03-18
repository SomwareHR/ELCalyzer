# ELCalyzer

ESETLogCollector "analyzer"



## Description

Main idea behind this is:

+ When solving issues with ESET's program, I need to frequently check same data over and over again..
+ ..mainly I never write data down so I have to take a look or twenty back into log files
+ there is like zillion log files and I never remember which file holds the data I need at the moment

Thus - ELCalyzer. ELCalyzer displays several most frequently searched info from various log files collected by ESET Log Collector (ELC).



## Prerequisites

+ Tested with Powershell 7 on Windows (some features will work on v.5)
+ [Powershell 7 installation](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)
+ ELC.EXE in path or folder. Can be downloaded with parameter "-DownloadELC" or [manually](https://www.eset.com/int/support/log-collector/)
+ Run as administrator (for conversion)



## Usage

+ [Download and run ELC ESETLogCollector](https://www.eset.com/int/support/log-collector/)
+ Unpack logs to a temporary folder ("C:\Temp\ELC\")
+ Run PWSH and change directory to "C:\Temp\ELC\" ("metadata.txt" and "info.xml" must be in that folder)
+ Run script: `.\ELCalyzer.ps1 -Everything`
+    or `.\ELCalyzer.ps1 -ExecutionPolicy Bypass -Everything`



## Command-line parameters

Default: `none`



### Parameters

| Parameter                      |
|--------------------------------|
| `Get-Help ELCalyzer.ps1 -full` |
| -Help                          |
| -Conversion                    |
| -LicInfo                       |
| -OSInfo                        |
| -ProgramInfo                   |
| -NetworkInfo                   |
| -WindowsUpdate                 |
| -VersionHistory                |
| -RebootHistory                 |
| -Hosts                         |
| -ScheduledTasks                |
| -RunningProcesses              |
| -ThreatsInfo                   |
| -FeaturesState                 |
| -IncompatibleSoftware          |
| -Errors                        |
| -DownloadELC                   |
| -Expand                        |
| -ExpandMore                    |
| -Everything                    |
| -ShowModules                   |



## Examples

| Command (line parameter)                    | What does it do                                                 |
|---------------------------------------------|-----------------------------------------------------------------|
| .\ELCalyzer.ps1 -LicInfo                    | displays license info (PLID, SeatID)                            |
| .\ELCalyzer.ps1 -Convert -ThreatsInfo       | convert DAT to XML, EVTX to CSV and then display last 5 threats |
| pwsh -file elcalyzer.ps1 -all >redirect.txt | redirect output to a file                                       |
| pwsh -file elcalyzer.ps1 -all \| clip       | (Windows) redirect output to a clipboard                        |



## Demo

![Output screen](ELCalyzer1.png)



## ToDo


### ToDo - Priority: High

+ Create more detailed help pages for every function


### ToDo - Priority: Middle

+ "-EnumerateFiles" ... Enumerate ELC's log files and check if everything was collected


### Priority: Low

+ Implement SomWare's ARSE(tm) (ARtificial Stupidity Engine) to suggest a solution based on info found in logs



###### Info

+ ELCalyzer v22.0314.16 Beta
+ https://github.com/SomwareHR/ELCalyzer
+ (C)2022 SomwareHR
+ License: MIT
+ SWID#20220303091402
