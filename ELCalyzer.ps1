<#

.SYNOPSIS
ELCalyzer v.22.0314.16 Beta
ESETLogCollector "logs analyzer"

.DESCRIPTION
ELCalyzer displays most frequently used data from uncompressed logs collected by ESET Log Collector (ELC).
Script must be run from ELC's root directory (where "metadata.txt" and "info.xml" files are).
Script should skip any nonexistent file and continue analyzing next one.
(C)2022 SomwareHR ... https://github.com/SomwareHR/ELCalyzer ... License: MIT ... SWID#20220303091402

Prerequisites:

+ Windows, Powershell 7 (some functions will work in Powershell 5, too)
+ Download pwsh7: https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows

Changelog:

+ 22.0314.16 ... added  : RunningProcesses
+ 22.0314.15 ... added  : ScheduledTasks
+ 22.0314.10 ... added  : Hosts
+ 22.0311.16 ... added  : Expand, ExpandMore
+ 22.0311.09 ... added  : NetworkInfo
+ 22.0310.11 ... added  : IncompatibleSoftware
+ 22.0310.10 ... changed: Conversion now lists files and opens ELC in other window
+ 22.0309.10 ... fixed  : LicenseInfo >> case with multiple licenses and Expiration dates
+ 22.0308.14 ... added  : FeaturesState ... list inactive / non-integrated modules
+ 22.0304.13 ... added  : LicenseInfo displays licensed product name
+ 22.0304.13 ... added  : LicenseInfo displays license expiration
+ 22.0304.13 ... added  : LicenseInfo displays multiple WebSeatIDs
+ 22.0304.09 ... added  : WindowsUpdate
+ 22.0304.09 ... changed: LicenseInfo displays PLID from three possible locations
+ 22.0303.14 ... added  : VersionHistory shows limited number of items (limit = $ItemsLimit) just like ThreatsInfo
+ 22.0303.14 ... changed: moved DownloadELC to top so it can be executed without need to have log files in folder
+ 22.0303.14 ... fixed  : Error001 was checking wrong file, and referring to other
+ 22.0303.10 ... init   : created Github repository

.PARAMETER Help
Short help

.PARAMETER Conversion
Convert .DAT  to .TXT
Convert .DAT  to .XML
Convert .EVTX to .CSV

.PARAMETER DownloadELC
Download ESETLogCollector and save it to ELC.EXE in current folder.
https://download.eset.com/com/eset/tools/diagnosis/log_collector/latest/esetlogcollector.exe

.PARAMETER LicInfo
Self-explanatory

.PARAMETER OSInfo
Self-explanatory

.PARAMETER ProgramInfo
Self-explanatory

.PARAMETER NetworkInfo
Self-explanatory

.PARAMETER WindowsUpdate
Shows "two KBs" and the total of updates

.PARAMETER RebootHistory
Show history of computer reboots (System:EventID:6005)

.PARAMETER VersionHistory
History of program's upgrades

.PARAMETER Hosts
Content of HOSTS file

.PARAMETER ScheduledTasks
List of, well, scheduled tasks (risk level 5-9)

.PARAMETER RunningProcesses
List of, well, running processes (risk level 5-9)

.PARAMETER ThreatsInfo
Show last 5 threats from "virlog.dat"
Prerequisite: -convert

.PARAMETER FeaturesState
Show inactive, not integrated modules

.PARAMETER IncompatibleSoftware
Lists known 3rd parties which cause troubles.
Based on keywords ("security", "antivirus", etc).

.PARAMETER Errors
List limited number of errors from various files

.PARAMETER All
Perform all above.
Does not include -Convert and -ShowModules but one can combine parameters (see examples)

.PARAMETER ShowModules
Lists all ESET security program modules

.PARAMETER Expand
Spread output a little bit

.PARAMETER ExpandMore
Spread output a little bit more than a little bit

.INPUTS
n/a

.OUTPUTS
Text

.EXAMPLE
PS> ELCalyzer.ps1 --LicInfo ... displays license info (PLID, SeatID)

.EXAMPLE
PS> ELCalyzer.ps1 --Convert -ThreatsInfo ... convert DAT to XML, EVTX to CSV and then display last 5 threats

.EXAMPLE
pwsh -file elcalyzer.ps1 -all > redirect.txt ... redirect output to a file
pwsh -file elcalyzer.ps1 -all | clip ... (Windows) redirect output to a clipboard

#>





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.                                                 888
# 888   Y88b                                                888
# 888    888                                                888
# 888   d88P 8888b.  888d888 8888b.  88888b.d88b.   .d88b.  888888 .d88b.  888d888 .d8888b
# 8888888P"     "88b 888P"      "88b 888 "888 "88b d8P  Y8b 888   d8P  Y8b 888P"   88K
# 888       .d888888 888    .d888888 888  888  888 88888888 888   88888888 888     "Y8888b.
# 888       888  888 888    888  888 888  888  888 Y8b.     Y88b. Y8b.     888          X88
# 888       "Y888888 888    "Y888888 888  888  888  "Y8888   "Y888 "Y8888  888      88888P'
# -----------------------------------------------------------------------------------------------------------------------------

Param(

  [Parameter ( Mandatory=$False , HelpMessage="Le help")]
  [Alias("h")]
  [ValidateNotNullOrEmpty()]
  [switch]$Help=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Converts DAT > TXT and EVTX > CSV")]
  [Alias("k" , "c" , "convert" , "con", "konvertiraj", "konverzija", "kon")]
  [ValidateNotNullOrEmpty()]
  [switch]$Conversion=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Download ESETLogCollector")]
  [Alias("dl","elc","getelc")]
  [ValidateNotNullOrEmpty()]
  [switch]$DownloadELC=$False,

  [Parameter ( Mandatory=$False , HelpMessage="License info")]
  [Alias("li" , "lic")]
  [ValidateNotNullOrEmpty()]
  [switch]$LicInfo=$False,

  [Parameter ( Mandatory=$False , HelpMessage="OS info")]
  [Alias("os")]
  [ValidateNotNullOrEmpty()]
  [switch]$OSInfo=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Program info")]
  [Alias("pi","program")]
  [ValidateNotNullOrEmpty()]
  [switch]$ProgramInfo=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Network info")]
  [Alias("ni","net", "network")]
  [ValidateNotNullOrEmpty()]
  [switch]$NetworkInfo=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Windows Update")]
  [Alias("wu")]
  [ValidateNotNullOrEmpty()]
  [switch]$WindowsUpdate=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Show reboot history")]
  [Alias("rh" , "boot", "reboots")]
  [ValidateNotNullOrEmpty()]
  [switch]$RebootHistory=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Show versions history")]
  [Alias("vh","ver","versions")]
  [ValidateNotNullOrEmpty()]
  [switch]$VersionHistory=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Threats info")]
  [Alias("ti","threats","malware","prijetnje")]
  [ValidateNotNullOrEmpty()]
  [switch]$ThreatsInfo=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Features state")]
  [Alias("fs","feat","inactive")]
  [ValidateNotNullOrEmpty()]
  [switch]$FeaturesState=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Incompatible software")]
  [Alias("is","incompat","troubles","3rd")]
  [ValidateNotNullOrEmpty()]
  [switch]$IncompatibleSoftware=$False,

  [Parameter ( Mandatory=$False , HelpMessage="List errors")]
  [Alias("err")]
  [ValidateNotNullOrEmpty()]
  [switch]$Errors=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Display HOSTS file")]
  [Alias("ho")]
  [ValidateNotNullOrEmpty()]
  [switch]$Hosts=$False,

  [Parameter ( Mandatory=$False , HelpMessage="List of scheduled tasks")]
  [Alias("st","sched","task","tasks")]
  [ValidateNotNullOrEmpty()]
  [switch]$ScheduledTasks=$False,

  [Parameter ( Mandatory=$False , HelpMessage="List of running processes")]
  [Alias("rp","run","process")]
  [ValidateNotNullOrEmpty()]
  [switch]$RunningProcesses=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Show all info")]
  [Alias("sve","all")]
  [ValidateNotNullOrEmpty()]
  [switch]$Everything=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Expand output a bit")]
  [Alias("exp")]
  [ValidateNotNullOrEmpty()]
  [switch]$Expand=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Expand more")]
  [Alias("exm")]
  [ValidateNotNullOrEmpty()]
  [switch]$ExpandMore=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Show modules")]
  [Alias("sm","modules")]
  [ValidateNotNullOrEmpty()]
  [switch]$ShowModules=$False

)





# -----------------------------------------------------------------------------------------------------------------------------
#  .d8888b.                             888           d88P 888     888
# d88P  Y88b                            888          d88P  888     888
# 888    888                            888         d88P   888     888
# 888         .d88b.  88888b.  .d8888b  888888     d88P    Y88b   d88P 8888b.  888d888
# 888        d88""88b 888 "88b 88K      888       d88P      Y88b d88P     "88b 888P"
# 888    888 888  888 888  888 "Y8888b. 888      d88P        Y88o88P  .d888888 888
# Y88b  d88P Y88..88P 888  888      X88 Y88b.   d88P          Y888P   888  888 888
#  "Y8888P"   "Y88P"  888  888  88888P'  "Y888 d88P            Y8P    "Y888888 888
# -----------------------------------------------------------------------------------------------------------------------------
Set-StrictMode -Version 2.0
$Script:DefaultErrorActionPreference = "Ignore"
$ErrorActionPreference = $Script:DefaultErrorActionPreference
$CrLf           = "`r`n"
$FakeIndent     = 32
$color_Data     = "Cyan"
$color_TitleFG  = "White"
$color_TitleBG  = "Darkgray"
$color_Error    = "Red"
$ItemsLimit     = 5 # show X items






# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.          d8b          888  88888888888 d8b 888    888
# 888   Y88b         Y8P          888      888     Y8P 888    888
# 888    888                      888      888         888    888
# 888   d88P 888d888 888 88888b.  888888   888     888 888888 888  .d88b.
# 8888888P"  888P"   888 888 "88b 888      888     888 888    888 d8P  Y8b
# 888        888     888 888  888 888      888     888 888    888 88888888
# 888        888     888 888  888 Y88b.    888     888 Y88b.  888 Y8b.
# 888        888     888 888  888  "Y888   888     888  "Y888 888  "Y8888
# -----------------------------------------------------------------------------------------------------------------------------
function fn_PrintTitle($Title)
{
  IF ($Expand -eq $True) { Write-Host "" }
  IF ($ExpandMore -eq $True) { Write-Host $CrLf $CrLf $CrLf}
  Write-Host ("-"*($FakeIndent+2)) -NoNewLine
  Write-Host "[$Title]" -NoNewLine -ForegroundColor $color_TitleFG -BackgroundColor $color_TitleBG
  Write-Host ("-"*(($Host.UI.RawUI.WindowSize.Width-$Title.Length)-5-$FakeIndent))
  IF ($ExpandMore -eq $True) { Write-Host "" }
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.          d8b          888    8888888b.           888
# 888   Y88b         Y8P          888    888  "Y88b          888
# 888    888                      888    888    888          888
# 888   d88P 888d888 888 88888b.  888888 888    888  8888b.  888888  8888b.
# 8888888P"  888P"   888 888 "88b 888    888    888     "88b 888        "88b
# 888        888     888 888  888 888    888    888 .d888888 888    .d888888
# 888        888     888 888  888 Y88b.  888  .d88P 888  888 Y88b.  888  888
# 888        888     888 888  888  "Y888 8888888P"  "Y888888  "Y888 "Y888888
# -----------------------------------------------------------------------------------------------------------------------------
function fn_PrintData ( $LosLabelos , $Data )
{
  Write-Host $LosLabelos -NoNewLine ("." * ($FakeIndent - $LosLabelos.Length )) ""
  Write-Host $Data -ForegroundColor $color_Data
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
#  .d8888b.                                                       d8b
# d88P  Y88b                                                      Y8P
# 888    888
# 888         .d88b.  88888b.  888  888  .d88b.  888d888 .d8888b  888  .d88b.  88888b.
# 888        d88""88b 888 "88b 888  888 d8P  Y8b 888P"   88K      888 d88""88b 888 "88b
# 888    888 888  888 888  888 Y88  88P 88888888 888     "Y8888b. 888 888  888 888  888
# Y88b  d88P Y88..88P 888  888  Y8bd8P  Y8b.     888          X88 888 Y88..88P 888  888
#  "Y8888P"   "Y88P"  888  888   Y88P    "Y8888  888      88888P' 888  "Y88P"  888  888 DAT2XML DAT2TXT EVTX2CSV
# -----------------------------------------------------------------------------------------------------------------------------

function fn_Conversion()
{
  fn_PrintTitle ( "Conversion (https://github.com/SomwareHR/ELCalyzer/Conversion.md) " )

  # ----- ELC logs ----- DAT2XML ----- #
  Write-Host "...please, wait, this can take a minute or nineteen..."
  $ListOfDATfiles  = (Get-ChildItem -Recurse -File "./ESET/Logs/*.dat").FullName
  #$DATCounter      = $ListOfDATfiles.Count
  $AntiCounter     = 0
  ForEach ($DATfile in $ListOfDATfiles) {
    $AntiCounter   = $AntiCounter + 1
    Write-Host $DATfile
    # cmd /c ELC.EXE /Bin2Xml "$DATfile" "$DATfile.xml"
    # cmd /c ELC.EXE /Bin2Txt "$DATfile" "$DATfile.txt"
    ELC.EXE /Bin2Xml "$DATfile" "$DATfile.xml" > tmp.tmp
    ELC.EXE /Bin2Txt "$DATfile" "$DATfile.txt" > tmp.tmp
  }
  fn_PrintData "DAT2XML / DAT2TXT" "Done"

  return

  # ----- EventViewer logs ----- EVTX2CSV ----- #
  Write-Host "...please, wait, this can take a minute or twentyone..."
  $ListOfEVTXfiles = (Get-ChildItem  -Recurse -File *.evtx).FullName
  $EVTXCounter     = $ListOfEVTXfiles.Count
  $AntiCounter     = 0
  ForEach ($EVTXfile in $ListOfEVTXfiles) {
    $AntiCounter   = $AntiCounter + 1
    Write-Host     $AntiCounter"/"$EVTXCounter"; "
    Get-WinEvent   -Path "$EVTXfile" | Export-CSV "$EVTXfile.csv"
  }
  Write-Host ""
  fn_PrintData "EVTX2CSV" "Done"
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 888      d8b          8888888           .d888
# 888      Y8P            888            d88P"
# 888                     888            888
# 888      888  .d8888b   888   88888b.  888888 .d88b.
# 888      888 d88P"      888   888 "88b 888   d88""88b
# 888      888 888        888   888  888 888   888  888
# 888      888 Y88b.      888   888  888 888   Y88..88P
# 88888888 888  "Y8888P 8888888 888  888 888    "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_LicInfo()
{
  fn_PrintTitle ( "LicenseInfo (https://github.com/SomwareHR/ELCalyzer/LicenseInfo.md) " )
  $WebSeatID1 = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='Key']//NODE[@NAME='WebSeatId']").VALUE
  $WebSeatID2 = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.AssociatedSeatId
  $WebSeatID3 = (Select-String -path "metadata.txt" -Pattern "Seat ID" -Raw).split(": ")[1]
  fn_PrintData "WebSeatIds found" $WebSeatID1"; "$WebSeatID2"; "$WebSeatID3

  $License1 = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='Key']//NODE[@NAME='WebLicensePublicId']").VALUE
  $License2 = (Select-String -path "metadata.txt" -Pattern "Public ID" -Raw).split(": ")[1]
  $License3 = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicensePublicId
  $License3ProductName = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicenseProductName
  $License4 = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicensePublicId
  $License4ProductName = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicenseProductName
  fn_PrintData "Licenses found" "$License1; $License2; $License3 $License3ProductName $License4 $License4ProductName"

  $LicenseExpirationDays = $null
  $LicenseExpirationDaysAll = $null
  $LicenseExpirationDays = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicenseExpirationDate

  ForEach ($LicenseExpirationDay in $LicenseExpirationDays) {
    $TMP1=[System.Convert]::ToInt32($LicenseExpirationDay,16) # epoch time in hex
    $TMP2=(([System.DateTimeOffset]::FromUnixTimeSeconds([int]$TMP1)).DateTime).ToString()  # epoch time to human
    $LicenseExpirationDaysAll=$LicenseExpirationDaysAll+$TMP2+"; "
  }

  fn_PrintData "Expiration date(s)" $LicenseExpirationDaysAll
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
#  .d88888b.   .d8888b.  d8b           .d888
# d88P" "Y88b d88P  Y88b Y8P          d88P"
# 888     888 Y88b.                   888
# 888     888  "Y888b.   888 88888b.  888888 .d88b.
# 888     888     "Y88b. 888 888 "88b 888   d88""88b
# 888     888       "888 888 888  888 888   888  888
# Y88b. .d88P Y88b  d88P 888 888  888 888   Y88..88P
#  "Y88888P"   "Y8888P"  888 888  888 888    "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_OSInfo()
{
  fn_PrintTitle ( "OSinfo (https://github.com/SomwareHR/ELCalyzer/OSinfo.md) " )
  $OS = $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSNAME']   ").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSVERSION']").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSTYPE']   ").Attributes["VALUE"].Value
  $HW = $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='PROCESSOR']").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='MEMORY']   ").Attributes["VALUE"].Value
  fn_PrintData "OS version" $OS
  fn_PrintData "HW info"   $HW
  $WebClientComputerName = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='WebClientComputerName']").VALUE
  fn_PrintData "Web client computer name" $WebClientComputerName
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 888       888 d8b               888                                 888     888               888          888
# 888   o   888 Y8P               888                                 888     888               888          888
# 888  d8b  888                   888                                 888     888               888          888
# 888 d888b 888 888 88888b.   .d88888  .d88b.  888  888  888 .d8888b  888     888 88888b.   .d88888  8888b.  888888 .d88b.
# 888d88888b888 888 888 "88b d88" 888 d88""88b 888  888  888 88K      888     888 888 "88b d88" 888     "88b 888   d8P  Y8b
# 88888P Y88888 888 888  888 888  888 888  888 888  888  888 "Y8888b. 888     888 888  888 888  888 .d888888 888   88888888
# 8888P   Y8888 888 888  888 Y88b 888 Y88..88P Y88b 888 d88P      X88 Y88b. .d88P 888 d88P Y88b 888 888  888 Y88b. Y8b.
# 888P     Y888 888 888  888  "Y88888  "Y88P"   "Y8888888P"   88888P'  "Y88888P"  88888P"   "Y88888 "Y888888  "Y888 "Y8888
#                                                                                 888
#                                                                                 888
#                                                                                 888
# -----------------------------------------------------------------------------------------------------------------------------
function fn_WindowsUpdate()
{
  fn_PrintTitle ( "WindowsUpdate (https://github.com/SomwareHR/ELCalyzer/WindowsUpdate.md) " )
  if ( ($file_SysInspector.DocumentElement.SelectSingleNode("//NODE[@VALUE='Hotfixes and Updates']").node.name | select-string KB4474419 -Quiet) -eq $True) { $KB4474419 = "KB4474419 present" } ELSE { $KB4474419 = "KB4474419 NOT present" }
  if ( ($file_SysInspector.DocumentElement.SelectSingleNode("//NODE[@VALUE='Hotfixes and Updates']").node.name | select-string KB4490628 -Quiet) -eq $True) { $KB4490628 = "KB4490628 present" } ELSE { $KB4490628 = "KB4490628 NOT present" }
  $WindowsUpdateCount=$file_SysInspector.DocumentElement.SelectSingleNode("//NODE[@VALUE='Hotfixes and Updates']").node.count
  fn_printData "Windows updates" "Total: $WindowsUpdateCount updates;   $KB4474419; $KB4490628; (NOT present = OK for modern OS)"

#  $file_SysInspector.DocumentElement.SelectNodes("//NODE[@VALUE='Hotfixes and Updates']")
# $file_SysInspector.DocumentElement.SelectSingleNode("//NODE[@VALUE='Hotfixes and Updates']").node.name
#  $License2 = (Select-String -path "metadata.txt" -Pattern "Public ID" -Raw).split(": ")[1]
#  $License3 = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='LICENSEINFO']").License.LicensePublicId
}

#  <NODE NAME="SUBSECTION" VALUE="Hotfixes and Updates" NAME_CAPTION="Update ID" TR="n=5001;v=5002;e=5003;V=5000" VALUE_CAPTION="Description" EXTRA_CAPTION="Installed" EVAL="5">
#   <NODE NAME="KB3063109" VALUE="" EXTRA="DEMO\administrator 3/13/2019" />

  #? KB4474419 (preuzimanje sa: https://www.catalog.update.microsoft.com/Search.aspx?q=4474419  – iz dostavljenih logova vidim da je ta zakrpa instalirana danas: "KB4474419" = "" HP-PC\HP 2/18/2022 ;)
  #? KB4490628 (preuzimanje sa: https://www.catalog.update.microsoft.com/Search.aspx?q=4490628  – ovu zakrpu nisam pronašao u popisu instaliranih zakrpa na tom računalu…)





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.                                                         8888888           .d888
# 888   Y88b                                                          888            d88P"
# 888    888                                                          888            888
# 888   d88P 888d888 .d88b.   .d88b.  888d888 8888b.  88888b.d88b.    888   88888b.  888888 .d88b.
# 8888888P"  888P"  d88""88b d88P"88b 888P"      "88b 888 "888 "88b   888   888 "88b 888   d88""88b
# 888        888    888  888 888  888 888    .d888888 888  888  888   888   888  888 888   888  888
# 888        888    Y88..88P Y88b 888 888    888  888 888  888  888   888   888  888 888   Y88..88P
# 888        888     "Y88P"   "Y88888 888    "Y888888 888  888  888 8888888 888  888 888    "Y88P"
#                                 888
#                            Y8b d88P
#                             "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_ProgramInfo()
{
  fn_PrintTitle ( "ProgramInfo (https://github.com/SomwareHR/ELCalyzer/ProgramInfo.md) " )
  $Program =  $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ProductName']").VALUE     + " " + `
              $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ProductVersion']").VALUE
  fn_PrintData "Program" $Program
  $InstallTime = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='InstallTime']").VALUE #     <NODE NAME="InstallTime" VALUE="0x61c1d917 (1640093975)" EVAL="1" />
  $InstallTime = $InstallTime.split("(")[1].split(")")[0]
  $InstallTime = (([System.DateTimeOffset]::FromUnixTimeSeconds([int]$InstallTime)).DateTime).ToString()
  fn_PrintData "Installed" $InstallTime

  $ScannerBuild   = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ScannerBuild']").VALUE
  $ScannerVersion = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ScannerVersion']").VALUE
  $ScannerBuild   = $ScannerBuild.split("(")[1].split(")")[0]
  $ScannerVersion = $ScannerVersion.split(" ")[1]
  fn_PrintData "Scanner" "v.$ScannerBuild $ScannerVersion"

  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 888b    888          888                                   888      8888888           .d888
# 8888b   888          888                                   888        888            d88P"
# 88888b  888          888                                   888        888            888
# 888Y88b 888  .d88b.  888888 888  888  888  .d88b.  888d888 888  888   888   88888b.  888888 .d88b.
# 888 Y88b888 d8P  Y8b 888    888  888  888 d88""88b 888P"   888 .88P   888   888 "88b 888   d88""88b
# 888  Y88888 88888888 888    888  888  888 888  888 888     888888K    888   888  888 888   888  888
# 888   Y8888 Y8b.     Y88b.  Y88b 888 d88P Y88..88P 888     888 "88b   888   888  888 888   Y88..88P
# 888    Y888  "Y8888   "Y888  "Y8888888P"   "Y88P"  888     888  888 8888888 888  888 888    "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_NetworkInfo()
{
  fn_PrintTitle ( "NetworkInfo (https://github.com/SomwareHR/ELCalyzer/NetworkInfo.md) " )
  $HostName = (Select-String -path "./config/network.txt" -Pattern "Host name"       -Raw).split(":")[1]
  $IPv4     = (Select-String -path "./config/network.txt" -Pattern "IPv4 Address"    -Raw).split(":")[1]
  $Subnet   = (Select-String -path "./config/network.txt" -Pattern "Subnet Mask"     -Raw).split(":")[1]
  $Gateway  = (Select-String -path "./config/network.txt" -Pattern "Default Gateway" -Raw).split(":")[1]
  $DNS      = (Select-String -path "./config/network.txt" -Pattern "DNS Servers"     -Raw).split(":")[1]
  fn_PrintData "IPv4" $HostName"   "$IPv4" / "$Subnet"   GW="$Gateway"   DNS="$DNS
}

# [string] $file_NetworkTXT    = Get-Content -Path ./config/network.txt -Encoding "UTF-8" -Raw

#   IPv4 Address. . . . . . . . . . . : 10.10.11.136(Preferred)
#   Subnet Mask . . . . . . . . . . . : 255.255.0.0
#   Default Gateway . . . . . . . . . : 10.10.0.1
#   DNS Servers . . . . . . . . . . . : 10.10.1.1
#                                       10.10.1.51



# -----------------------------------------------------------------------------------------------------------------------------
# 888     888                           d8b                   888    888 d8b          888
# 888     888                           Y8P                   888    888 Y8P          888
# 888     888                                                 888    888              888
# Y88b   d88P  .d88b.  888d888 .d8888b  888  .d88b.  88888b.  8888888888 888 .d8888b  888888 .d88b.  888d888 888  888
#  Y88b d88P  d8P  Y8b 888P"   88K      888 d88""88b 888 "88b 888    888 888 88K      888   d88""88b 888P"   888  888
#   Y88o88P   88888888 888     "Y8888b. 888 888  888 888  888 888    888 888 "Y8888b. 888   888  888 888     888  888
#    Y888P    Y8b.     888          X88 888 Y88..88P 888  888 888    888 888      X88 Y88b. Y88..88P 888     Y88b 888
#     Y8P      "Y8888  888      88888P' 888  "Y88P"  888  888 888    888 888  88888P'  "Y888 "Y88P"  888      "Y88888
#                                                                                                                 888
#                                                                                                            Y8b d88P
#                                                                                                             "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_VersionHistory()
{
  fn_PrintTitle ( "VersionHistory (https://github.com/SomwareHR/ELCalyzer/VersionHistory.md) " )
  $VersionHistory = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='VERSIONS']//Version")
  $AntiCounter    = 0
  ForEach ($Version in $VersionHistory) {
    $AntiCounter = $AntiCounter + 1
    $VersionInfo = $Version.Info | ConvertFrom-CSV -Header ("WebSeatID","Program","ProgID","Version","Maturity","LicType","OS","Lang")
    $DataZaPrint = (-join $Version.DateTime[0..9]) + " " + $VersionInfo.Program + " " + $VersionInfo.Version + " " + $VersionInfo.Maturity + "; " + $VersionInfo.LicType  + " " + $VersionInfo.OS
    Write-Host $DataZaPrint -ForegroundColor $color_Data
    IF ( $AntiCounter -eq $ItemsLimit) { Break }
  }
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.          888                        888    888      d8b          888
# 888   Y88b         888                        888    888      Y8P          888
# 888    888         888                        888    888                   888
# 888   d88P .d88b.  88888b.   .d88b.   .d88b.  888888 88888b.  888 .d8888b  888888 .d88b.  888d888 888  888
# 8888888P" d8P  Y8b 888 "88b d88""88b d88""88b 888    888 "88b 888 88K      888   d88""88b 888P"   888  888
# 888 T88b  88888888 888  888 888  888 888  888 888    888  888 888 "Y8888b. 888   888  888 888     888  888
# 888  T88b Y8b.     888 d88P Y88..88P Y88..88P Y88b.  888  888 888      X88 Y88b. Y88..88P 888     Y88b 888
# 888   T88b "Y8888  88888P"   "Y88P"   "Y88P"   "Y888 888  888 888  88888P'  "Y888 "Y88P"  888      "Y88888
#                                                                                                        888
#                                                                                                   Y8b d88P
#                                                                                                    "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_RebootHistory()
{
  fn_PrintTitle ( "RebootHistory (https://github.com/SomwareHR/ELCalyzer/RebootHistory.md) " )
  IF ( $DisplayHeaders -eq $False) {
    Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; ID="6005"} -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize -HideTableHeaders |Out-String).Trim() -ForegroundColor $color_Data
  }
  ELSE {
    Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; ID="6005"} -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize |Out-String).Trim() -ForegroundColor $color_Data
  }
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 888    888                   888
# 888    888                   888
# 888    888                   888
# 8888888888  .d88b.  .d8888b  888888 .d8888b
# 888    888 d88""88b 88K      888    88K
# 888    888 888  888 "Y8888b. 888    "Y8888b.
# 888    888 Y88..88P      X88 Y88b.       X88
# 888    888  "Y88P"   88888P'  "Y888  88888P'
# -----------------------------------------------------------------------------------------------------------------------------
function fn_Hosts()
{
  fn_PrintTitle("Hosts (https://github.com/SomwareHR/ELCalyzer/Hosts.md) ")
  $Hosts = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@VALUE='hosts']")
  fn_PrintData "Hosts" $hosts.node.Value
}





# -----------------------------------------------------------------------------------------------------------------------------
#  .d8888b.           888                    888          888               888 88888888888                888
# d88P  Y88b          888                    888          888               888     888                    888
# Y88b.               888                    888          888               888     888                    888
#  "Y888b.    .d8888b 88888b.   .d88b.   .d88888 888  888 888  .d88b.   .d88888     888   8888b.  .d8888b  888  888 .d8888b
#     "Y88b. d88P"    888 "88b d8P  Y8b d88" 888 888  888 888 d8P  Y8b d88" 888     888      "88b 88K      888 .88P 88K
#       "888 888      888  888 88888888 888  888 888  888 888 88888888 888  888     888  .d888888 "Y8888b. 888888K  "Y8888b.
# Y88b  d88P Y88b.    888  888 Y8b.     Y88b 888 Y88b 888 888 Y8b.     Y88b 888     888  888  888      X88 888 "88b      X88
#  "Y8888P"   "Y8888P 888  888  "Y8888   "Y88888  "Y88888 888  "Y8888   "Y88888     888  "Y888888  88888P' 888  888  88888P'
# -----------------------------------------------------------------------------------------------------------------------------
function fn_ScheduledTasks()
{
  fn_PrintTitle("Scheduled tasks, risk level 5-9 (https://github.com/SomwareHR/ELCalyzer/ScheduledTasks.md)")
  $ScheduledTasks = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@VALUE='System Scheduler Tasks']").Node
  ForEach ($Tasks in $ScheduledTasks) {
    IF ( $Tasks.Node.Eval -ge 5 ) {
      Write-Host $Tasks.Node.Eval,$Tasks.Node.Value -ForegroundColor $color_Data
    }
  }
}

#  Write-Host ":::"$ScheduledTasks
#  fn_PrintData "Scheduled tasks" $ScheduledTasks
#  <NODE NAME="SECTION" VALUE="System Scheduler Tasks" TR="V=5600;n=4151;v=4602" NAME_CAPTION="Information" VALUE_CAPTION="Value" TREE_ICON="10" PARENTS_ONLY="1" EVAL="9">
# <NODE NAME="Task" TR="N=5601" VALUE="c:\windows\system32\tasks\Microsoft\Windows\Server Manager\CleanupOldPerfLogs" EVAL="9">
#   <NODE NAME="Command line" TR="N=5602" VALUE="%systemroot%\system32\cscript.exe /B /nologo %systemroot%\system32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)" EVAL="9" LINK="908" MLINK="903,908" />





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888b.                             d8b                   8888888b.
# 888   Y88b                            Y8P                   888   Y88b
# 888    888                                                  888    888
# 888   d88P 888  888 88888b.  88888b.  888 88888b.   .d88b.  888   d88P 888d888 .d88b.   .d8888b .d88b.  .d8888b  .d8888b   .d88b.  .d8888b
# 8888888P"  888  888 888 "88b 888 "88b 888 888 "88b d88P"88b 8888888P"  888P"  d88""88b d88P"   d8P  Y8b 88K      88K      d8P  Y8b 88K
# 888 T88b   888  888 888  888 888  888 888 888  888 888  888 888        888    888  888 888     88888888 "Y8888b. "Y8888b. 88888888 "Y8888b.
# 888  T88b  Y88b 888 888  888 888  888 888 888  888 Y88b 888 888        888    Y88..88P Y88b.   Y8b.          X88      X88 Y8b.          X88
# 888   T88b  "Y88888 888  888 888  888 888 888  888  "Y88888 888        888     "Y88P"   "Y8888P "Y8888   88888P'  88888P'  "Y8888   88888P'
#                                                         888
#                                                    Y8b d88P
#                                                     "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_RunningProcesses()
{
  fn_PrintTitle ("Running processes, risk level 5-9 (https://github.com/SomwareHR/ELCalyzer/RunningProcesses.md)")
  $RunningProcesses = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@VALUE='Running Processes']//NODE[@NAME='Process']")
  ForEach ($Process in $RunningProcesses) {
    IF ( $Process.Eval -ge 5 ) {
      Write-Host $Process.Eval,$Process.CmdLine -ForegroundColor $color_Data
    }
  }
}
# <NODE NAME="SECTION" VALUE="Running Processes"


# -----------------------------------------------------------------------------------------------------------------------------
#  .d8888b.  888                             888b     d888               888          888
# d88P  Y88b 888                             8888b   d8888               888          888
# Y88b.      888                             88888b.d88888               888          888
#  "Y888b.   88888b.   .d88b.  888  888  888 888Y88888P888  .d88b.   .d88888 888  888 888  .d88b.  .d8888b
#     "Y88b. 888 "88b d88""88b 888  888  888 888 Y888P 888 d88""88b d88" 888 888  888 888 d8P  Y8b 88K
#       "888 888  888 888  888 888  888  888 888  Y8P  888 888  888 888  888 888  888 888 88888888 "Y8888b.
# Y88b  d88P 888  888 Y88..88P Y88b 888 d88P 888   "   888 Y88..88P Y88b 888 Y88b 888 888 Y8b.          X88
#  "Y8888P"  888  888  "Y88P"   "Y8888888P"  888       888  "Y88P"   "Y88888  "Y88888 888  "Y8888   88888P'
# -----------------------------------------------------------------------------------------------------------------------------
function fn_ShowModules()
{
  fn_PrintTitle ( "ShowModules (https://github.com/SomwareHR/ELCalyzer/ShowModules.md) " )
  $allProperties = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='MODULES']//LINE")
  foreach($Property in $allProperties) {
    Write-Host $($Property.NAME) $($Property.VALUE) "; " -NoNewline
  }
  Write-Host $CrLf
  Return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 88888888888 888                               888             8888888           .d888
#     888     888                               888               888            d88P"
#     888     888                               888               888            888
#     888     88888b.  888d888 .d88b.   8888b.  888888 .d8888b    888   88888b.  888888 .d88b.
#     888     888 "88b 888P"  d8P  Y8b     "88b 888    88K        888   888 "88b 888   d88""88b
#     888     888  888 888    88888888 .d888888 888    "Y8888b.   888   888  888 888   888  888
#     888     888  888 888    Y8b.     888  888 Y88b.       X88   888   888  888 888   Y88..88P
#     888     888  888 888     "Y8888  "Y888888  "Y888  88888P' 8888888 888  888 888    "Y88P"
# -----------------------------------------------------------------------------------------------------------------------------
function fn_ThreatsInfo()
{
  fn_PrintTitle ( "ThreatsInfo - VirLog.dat (https://github.com/SomwareHR/ELCalyzer/ThreatsInfo.md) " )
  IF (!(Test-Path -Path "./ESET/Logs/Common/virlog.dat.xml" -PathType Leaf)) {
    Write-Host "Error003a - ./ESET/Logs/Common/virlog.dat is not converted yet. Execute   [$PSCommandPath -conversion]   first. Or.." -Foreground $color_Error
    Write-Host "Error003b - ./ESET/Logs/Common/virlog.dat file does not have any record (it is 56 bytes long/large/wide/tall/heavy). Or.." -Foreground $color_Error
    Write-Host "Error003c - ./ESET/Logs/Common/virlog.dat file does not exist." -Foreground $color_Error
    cmd /c dir ".\ESET\Logs\Common\*.dat"
    Write-Host $PSCommandPath
    Exit
  }

  $file_virlogDatXml = Select-Xml -Path "./ESET/Logs/Common/virlog.dat.xml" -XPath "/Events/Event"
  $Counter = $ItemsLimit  # max number of threat-logs to show
  $Tablica = ""
  $Heder   = "Date","Name","Threat","Action","SHA"
  ForEach ($virlog in $file_virlogDatXml) {
    $Tablica = $Tablica + $VirLog.Node.Col8 + ";" + $VirLog.Node.Name + ";" + $VirLog.Node.Threat + ";" + $VirLog.Node.Action + ";" + "https://virustotal.com/gui/search/"+$VirLog.Node.Col7 + $CrLf
    $Counter = $Counter - 1
    IF ( $Counter -eq 0 ) { Break }
  }
  IF ($DisplayHeaders -eq $False) {
    Write-Host (((ConvertFrom-CSV $Tablica -Delimiter ";" -Header $Heder | Format-Table -HideTableHeaders -AutoSize ) | Out-String).Trim()) -ForegroundColor $color_Data
  }
  ELSE {
    Write-Host (((ConvertFrom-CSV $Tablica -Delimiter ";" -Header $Heder | Format-Table -AutoSize ) | Out-String).Trim()) -ForegroundColor $color_Data
  }

  Return
}






# -----------------------------------------------------------------------------------------------------------------------------
# 8888888888                888                                       .d8888b.  888             888
# 888                       888                                      d88P  Y88b 888             888
# 888                       888                                      Y88b.      888             888
# 8888888  .d88b.   8888b.  888888 888  888 888d888 .d88b.  .d8888b   "Y888b.   888888  8888b.  888888 .d88b.
# 888     d8P  Y8b     "88b 888    888  888 888P"  d8P  Y8b 88K          "Y88b. 888        "88b 888   d8P  Y8b
# 888     88888888 .d888888 888    888  888 888    88888888 "Y8888b.       "888 888    .d888888 888   88888888
# 888     Y8b.     888  888 Y88b.  Y88b 888 888    Y8b.          X88 Y88b  d88P Y88b.  888  888 Y88b. Y8b.
# 888      "Y8888  "Y888888  "Y888  "Y88888 888     "Y8888   88888P'  "Y8888P"   "Y888 "Y888888  "Y888 "Y8888
# -----------------------------------------------------------------------------------------------------------------------------
function fn_FeaturesState()
{
  fn_PrintTitle ("FeaturesState (https://github.com/SomwareHR/ELCalyzer/FeaturesState.md) ")
  $Inactives        = $Null
  $InactiveFeatures = (Select-String -Path "./features_state.txt" -Pattern " Inactive" -Raw -AllMatches -Encoding "utf-8")
  ForEach ($Feature in $InactiveFeatures) {
    $Feature   = $Feature -replace "\s+", ";" -Replace ":",""
    $Inactives = $Inactives + ($Feature.Split(";")[1]) + "; "
  }
  fn_PrintData "Inactive modules" $Inactives

  $Inactives        = $Null
  $InactiveFeatures = (Select-String -Path "./features_state.txt" -Pattern ": Not integrated" -Raw -AllMatches -Encoding "utf-8")
  ForEach ($Feature in $InactiveFeatures) {
    $Feature   = $Feature -replace "\s+", ";" -Replace ":",""
    $Inactives = $Inactives + ($Feature.Split(";")[1]) + "; "
  }
  fn_PrintData "Not integrated modules" $Inactives
  return
}





# -----------------------------------------------------------------------------------------------------------------------------
# 8888888                                                           888    d8b 888      888          .d8888b.            .d888 888
#   888                                                             888    Y8P 888      888         d88P  Y88b          d88P"  888
#   888                                                             888        888      888         Y88b.               888    888
#   888   88888b.   .d8888b .d88b.  88888b.d88b.  88888b.   8888b.  888888 888 88888b.  888  .d88b.  "Y888b.    .d88b.  888888 888888 888  888  888  8888b.  888d888 .d88b.
#   888   888 "88b d88P"   d88""88b 888 "888 "88b 888 "88b     "88b 888    888 888 "88b 888 d8P  Y8b    "Y88b. d88""88b 888    888    888  888  888     "88b 888P"  d8P  Y8b
#   888   888  888 888     888  888 888  888  888 888  888 .d888888 888    888 888  888 888 88888888      "888 888  888 888    888    888  888  888 .d888888 888    88888888
#   888   888  888 Y88b.   Y88..88P 888  888  888 888 d88P 888  888 Y88b.  888 888 d88P 888 Y8b.    Y88b  d88P Y88..88P 888    Y88b.  Y88b 888 d88P 888  888 888    Y8b.
# 8888888 888  888  "Y8888P "Y88P"  888  888  888 88888P"  "Y888888  "Y888 888 88888P"  888  "Y8888  "Y8888P"   "Y88P"  888     "Y888  "Y8888888P"  "Y888888 888     "Y8888
#                                                 888
#                                                 888
#                                                 888
# -----------------------------------------------------------------------------------------------------------------------------
function fn_IncompatibleSoftware()
{
  fn_PrintTitle ("IncompatibleSoftware (https://github.com/SomwareHR/ELCalyzer/IncompatibleSoftware.md) ")
  $IncompatibleSoftwarez=
    "fortigate",
    "fortinet",
    "forti",
    "norton",
    "mcafee",
    "malwarebytes",
    "panda",
    "antivirus",
    "firewall",
    "protection",
    "vpn",
    "checkpoint",
    "security",
    "virus",
    "kaspersky",
    "sophos",
    "somethingsomething"
  $InstalledSoftwarez = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@VALUE='Installed Software']").Node.Value
  ForEach ($IncompatibleSoftware in $IncompatibleSoftwarez) {
    IF ($InstalledSoftwarez -match $IncompatibleSoftware) {
      #Write-Host $IncompatibleSoftware
      Write-Host ($InstalledSoftwarez | Select-String -Pattern "$IncompatibleSoftware" -Encoding "UTF-8")"; " -NoNewLine
    }
  }
  Write-Host ""
  return
}






# -----------------------------------------------------------------------------------------------------------------------------
# 8888888888
# 888
# 888
# 8888888    888d888 888d888 .d88b.  888d888 .d8888b
# 888        888P"   888P"  d88""88b 888P"   88K
# 888        888     888    888  888 888     "Y8888b.
# 888        888     888    Y88..88P 888          X88
# 8888888888 888     888     "Y88P"  888      88888P'
# -----------------------------------------------------------------------------------------------------------------------------
function fn_Errors() {
  fn_PrintTitle ("Errors (https://github.com/SomwareHR/ELCalyzer/Errors.md) ")

  fn_PrintData "Warnlog.dat" ($file_WarnLogDat.DocumentElement.SelectNodes("//Event[@Level='Error']").Event | Sort-Object -Unique)
  fn_PrintData "Warnlog.dat" ($file_WarnLogDat.DocumentElement.SelectNodes("//Event[@Level='ErrorCritical']").Event | Sort-Object -Unique)
  fn_PrintData "Warnlog.dat" ($file_WarnLogDat.DocumentElement.SelectNodes("//Event[@Level='Warning']").Event | Sort-Object -Unique)
  fn_PrintData "Warnlog.dat" ($file_WarnLogDat.DocumentElement.SelectNodes("//Event[@Level='SecWarning']").Event | Sort-Object -Unique)

  fn_PrintData "Audit.dat"   ($file_AuditDat.DocumentElement.SelectNodes("//Event[@Level='Error']").Event | Sort-Object -Unique)
  fn_PrintData "Audit.dat"   ($file_AuditDat.DocumentElement.SelectNodes("//Event[@Level='ErrorCritical']").Event | Sort-Object -Unique)
  fn_PrintData "Audit.dat"   ($file_AuditDat.DocumentElement.SelectNodes("//Event[@Level='Warning']").Event | Sort-Object -Unique)
  fn_PrintData "Audit.dat"   ($file_AuditDat.DocumentElement.SelectNodes("//Event[@Level='SecWarning']").Event | Sort-Object -Unique)

  # ----- Critical ----- #

  $Criticalz = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="1"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  $Errorz    = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="2"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  $Warningz  = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="3"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  fn_PrintData "SysEvtx-Critical" $CrLf$Criticalz
  fn_PrintData "SysEvtx-Errors"   $CrLf$Errorz
  fn_PrintData "SysEvtx-Warnings" $CrLf$Warningz

  $Criticalz = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/Application.evtx' ; Level="1"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  $Errorz    = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/Application.evtx' ; Level="2"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  $Warningz  = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/Application.evtx' ; Level="3"} | Select-Object ID, ProviderName, Message -Unique -First 10 | Format-Table -AutoSize -HideTableHeaders | Out-String ).Trim()
  fn_PrintData "AppEvtx-Critical" $CrLf$Criticalz
  fn_PrintData "AppEvtx-Errors"   $CrLf$Errorz
  fn_PrintData "AppEvtx-Warnings" $CrLf$Warningz

}


#  Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="2"} -MaxEvents 5)
#  $Criticalz = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="1"} | Select-Object ID, ProviderName, Message -Unique | Sort-Object -top 5 | Format-Table -AutoSize -HideTableHeaders | Out-String).Trim()
#  $Errorz    = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="2"} | Select-Object ID, ProviderName, Message -Unique | Sort-Object -top 5 | Format-Table -AutoSize -HideTableHeaders | Out-String).Trim()
#  $Warningz  = ( Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; Level="3"} | Select-Object ID, ProviderName, Message -Unique | Sort-Object -top 5 | Format-Table -AutoSize -HideTableHeaders | Out-String).Trim()



#   Get-WinEvent -Path "./Windows/Logs/System.evtx" -FilterXPath "*[System[(Level=1)]]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

#   Get-WinEvent -Path "./Windows/Logs/System.evtx" -FilterXPath "*[System[(Level=1)]]" # 1=Critical 2=Error 3=Warning
#
#   $Query = "<QueryList>
#     <Query Id='0' Path='Application'>
#       <Select Path='Application'>*[System[TimeCreated[@SystemTime >= '$(Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0 -Format "yyyy-MM-ddTHH:mm:ss.fffZ" -AsUTC)']]]</Select>
#     </Query>
#   </QueryList>"
#   Get-WinEvent -FilterXML $Query | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
#
#   # Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; ID="6005"} -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize -HideTableHeaders |Out-String).Trim() -ForegroundColor $color_Data
#   # Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' } -FilterXPath "*[System[(Level=1)]]"
#   # Write-Host (Get-WinEvent -LogName 'Application' -FilterXPath "*[System[(Level=1)]]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
#
# # keywords: failed, blocked, warning, failure, catastrophic, crashed





# -----------------------------------------------------------------------------------------------------------------------------
#          888b     d888        d8888 8888888 888b    888
#          8888b   d8888       d88888   888   8888b   888
#          88888b.d88888      d88P888   888   88888b  888
#          888Y88888P888     d88P 888   888   888Y88b 888
#          888 Y888P 888    d88P  888   888   888 Y88b888
#          888  Y8P  888   d88P   888   888   888  Y88888
#          888   "   888  d8888888888   888   888   Y8888
# 88888888 888       888 d88P     888 8888888 888    Y888 88888888
# -----------------------------------------------------------------------------------------------------------------------------
Write-Host ("="*($Host.UI.RawUI.WindowSize.Width-31)) "*** START ***" (Get-Date -UFormat %Y%m%d-%H%M%S)
Write-Host @"
####### #        #####
#       #       #     #   ##   #      #   # ###### ###### #####
#       #       #        #  #  #       # #      #  #      #    #
#####   #       #       #    # #        #      #   #####  #    #
#       #       #       ###### #        #     #    #      #####
#       #       #     # #    # #        #    #     #      #   #
####### #######  #####  #    # ######   #   ###### ###### #    #
"@


IF ( $DownloadELC    -eq $True ) {
  IF (!(Test-Path -Path "elc.exe" -PathType Leaf)) {
    Write-Host "Downloading ESETLogCollector.."

  }
}

if ( $Help     -eq $True ) {
  fn_PrintTitle("Parameters")
  Write-Host "Use one of following parameters or see more detailed help by:   Get-Help ELCalyzer.ps1 -full"
  Write-Host "-Help                 -h  :" $Help
  Write-Host "-Conversion           -con:" $Conversion
  Write-Host "-LicInfo              -li :" $LicInfo
  Write-Host "-OSInfo               -os :" $OSInfo
  Write-Host "-ProgramInfo          -pi :" $ProgramInfo
  Write-Host "-NetworkInfo          -ni :" $NetworkInfo
  Write-Host "-WindowsUpdate        -wu :" $WindowsUpdate
  Write-Host "-VersionHistory       -vh :" $VersionHistory
  Write-Host "-RebootHistory        -rh :" $RebootHistory
  Write-Host "-Hosts                -ho :" $Hosts
  Write-Host "-ScheduledTasks       -ho :" $ScheduledTasks
  Write-Host "-RunningProcesses     -ho :" $RunningProcesses
  Write-Host "-ThreatsInfo          -ti :" $ThreatsInfo
  Write-Host "-FeaturesState        -fs :" $FeaturesState
  Write-Host "-IncompatibleSoftware -is :" $IncompatibleSoftware
  Write-Host "-Errors               -err:" $Errors
  Write-Host "-DownloadELC          -dl :" $DownloadELC
  Write-Host "-Expand               -exp:" $Expand
  Write-Host "-ExpandMore           -exm:" $ExpandMore
  Write-Host "-Everything           -all:" $Everything
  Write-Host "-ShowModules          -sm :" $ShowModules
  exit
}

IF (!(Test-Path -Path "info.xml"     -PathType Leaf)) { Write-Host "Error001 - Wrong folder? File info.xml not found"     -Foreground $color_Error ; Exit }
IF (!(Test-Path -Path "metadata.txt" -PathType Leaf)) { Write-Host "Error002 - Wrong folder? File metadata.txt not found" -Foreground $color_Error ; Exit }
[xml]    $file_SysInspector  = Get-Content -Path "./Config/SysInspector.xml" -Encoding "UTF-8" -Raw
[xml]    $file_InfoXML       = Get-Content -Path "./info.xml" -Encoding "UTF-8" -Raw
[xml]    $file_WarnLogDat    = Get-Content -Path "./eset/logs/common/warnlog.dat.xml" -Encoding "UTF-8" -Raw
[xml]    $file_VirLogDat     = Get-Content -Path "./eset/logs/common/virlog.dat.xml" -Encoding "UTF-8" -Raw
[xml]    $file_AuditDat      = Get-Content -Path "./eset/logs/common/audit.dat.xml" -Encoding "UTF-8" -Raw
[string] $file_NetworkTXT    = Get-Content -Path ./config/network.txt -Encoding "UTF-8" -Raw
#[string] $file_FeaturesState = Get-Content -Path "./features_state.txt" -Encoding "UTF-8" -Raw
#         $file_MetadataTXT   = Get-Content -Path "./metadata.txt" -Encoding "UTF-8" -Raw


IF ( $Conversion            -eq $True ) { fn_Conversion           }
IF ( $LicInfo               -eq $True ) { fn_LicInfo              }
IF ( $OSInfo                -eq $True ) { fn_OSInfo               }
IF ( $ProgramInfo           -eq $True ) { fn_ProgramInfo          }
IF ( $NetworkInfo           -eq $True ) { fn_NetworkInfo          }
IF ( $WindowsUpdate         -eq $True ) { fn_WindowsUpdate        }
IF ( $RebootHistory         -eq $True ) { fn_RebootHistory        }
IF ( $VersionHistory        -eq $True ) { fn_VersionHistory       }
IF ( $Hosts                 -eq $True ) { fn_Hosts                }
IF ( $ScheduledTasks        -eq $True ) { fn_ScheduledTasks       }
IF ( $RunningProcesses      -eq $True ) { fn_RunningProcesses     }
IF ( $ThreatsInfo           -eq $True ) { fn_ThreatsInfo          }
IF ( $FeaturesState         -eq $True ) { fn_FeaturesState        }
IF ( $IncompatibleSoftware  -eq $True ) { fn_IncompatibleSoftware }
IF ( $Errors                -eq $True ) { fn_Errors               }
IF ( $ShowModules           -eq $True ) { fn_ShowModules          }

IF ( $Everything            -eq $True ) { # ALL
  fn_LicInfo               # -li
  fn_OSInfo                # -os
  fn_ProgramInfo           # -pi
  fn_NetworkInfo           # -ni
  fn_WindowsUpdate         # -wu
  fn_RebootHistory         # -rh
  fn_VersionHistory        # -vh
  fn_Hosts                 # -ho
  fn_ScheduledTasks        # -st
  fn_RunningProcesses      # -rp
  fn_ThreatsInfo           # -ti
  fn_FeaturesState         # -fs
  fn_IncompatibleSoftware  # -is
  fn_Errors                # -er
# fn_ShowModules           # -sm
}





# -----------------------------------------------------------------------------------------------------------------------------
# 88888888888 888               8888888888               888
#     888     888               888                      888
#     888     888               888                      888
#     888     88888b.   .d88b.  8888888    88888b.   .d88888
#     888     888 "88b d8P  Y8b 888        888 "88b d88" 888
#     888     888  888 88888888 888        888  888 888  888
#     888     888  888 Y8b.     888        888  888 Y88b 888
#     888     888  888  "Y8888  8888888888 888  888  "Y88888
# -----------------------------------------------------------------------------------------------------------------------------
Write-Host ("="*($Host.UI.RawUI.WindowSize.Width-33)) "*** THE END ***" (Get-Date -UFormat %Y%m%d-%H%M%S)
exit

# SWID#20220303091402
# copy K:\Backup\OneDrive\tomo.testira@outlook.com\OneDrive\zz-NORT\Dev22\ELCalyzer\ELCalyzer.ps1 K:\Backup\OneDrive\tomo.testira@outlook.com\OneDrive\zz-NORT\Dev22\ELCalyzer\BEKZ\ELCalyzer.ps1-22.0304.13B




#
#
