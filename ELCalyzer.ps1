<#

.SYNOPSIS
ELCalyzer v.22.0303.10 Beta
ESETLogCollector "analyzer"

.DESCRIPTION
ELCalyzer displays most frequently used data from uncompressed logs collected by ESET Log Collector (ELC).
Script must be run from ELC's root directory (where metadata.txt and info.xml files are).
Script should simply skip any nonexistent file.
(C)SomwareHR ... https://github.com/SomwareHR/elcalyzer ... License: MIT ... SWID#20220303091402

.PARAMETER Help
Short help

.PARAMETER Conversion
Convert .DAT to .TXT and .EVTX to .CSV

.PARAMETER DownloadELC
Download ESETLogCollector and save it to ELC.EXE in current folder.
https://download.eset.com/com/eset/tools/diagnosis/log_collector/latest/esetlogcollector.exe

.PARAMETER LicInfo
Displays license info

.PARAMETER OSInfo
Well.. displays OS info

.PARAMETER ProgramInfo
ESET's program(s) info

.PARAMETER RebootHistory
Show history of computer reboots (System:EventID:6005)

.PARAMETER VersionHistory
History of program's upgrades

.PARAMETER ThreatsInfo
Show last 5 threats from "virlog.dat"
Prerequisite: -convert

.PARAMETER All
Show all info above.
Does not include -Convert but one can combine parameters (see examples)

.PARAMETER ShowModules
Lists all ESET security program modules

.PARAMETER DisplayHeaders
Display table headers where possible (Format-Table)

.INPUTS
n/a

.OUTPUTS
Text file

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

  [Parameter ( Mandatory=$False , HelpMessage="Show all info")]
  [Alias("sve","all")]
  [ValidateNotNullOrEmpty()]
  [switch]$Everything=$False,

  [Parameter ( Mandatory=$False , HelpMessage="Display table headers")]
  [Alias("dh","headers")]
  [ValidateNotNullOrEmpty()]
  [switch]$DisplayHeaders=$False,

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
$MaximumThreats = 5 # show X last threats






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
  Write-Host ("-"*($FakeIndent+2)) -NoNewLine
  Write-Host "[$Title]" -NoNewLine -ForegroundColor $color_TitleFG -BackgroundColor $color_TitleBG
  Write-Host ("-"*(($Host.UI.RawUI.WindowSize.Width-$Title.Length)-5-$FakeIndent))
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
#  "Y8888P"   "Y88P"  888  888   Y88P    "Y8888  888      88888P' 888  "Y88P"  888  888 DAT2XML EVTX2CSV
# -----------------------------------------------------------------------------------------------------------------------------

function fn_Conversion()
{
  fn_PrintTitle ( "Conversion" )

  # ----- ELC logs ----- DAT2XML ----- #
  Write-Host "...please, wait, this can take a minute or nineteen..."
  Write-Host ".DAT to .XML .... " -NoNewLine
  $ListOfDATfiles  = (Get-ChildItem  -Recurse -File *.dat).FullName
  #$DATCounter      = $ListOfDATfiles.Count
  $AntiCounter     = 0
  ForEach ($DATfile in $ListOfDATfiles) {
    $AntiCounter   = $AntiCounter + 1
    ELC.EXE /Bin2Xml "$DATfile" "$DATfile.xml"
  }
  Write-Host "..DAT2XML done"

  # ----- EventViewer logs ----- EVTX2CSV ----- #
  Write-Host "...please, wait, this can take a minute or twentyone..."
  Write-Host ".EVTX to .CSV ... " -NoNewLine
  $ListOfEVTXfiles = (Get-ChildItem  -Recurse -File *.evtx).FullName
  $EVTXCounter     = $ListOfEVTXfiles.Count
  $AntiCounter     = 0
  ForEach ($EVTXfile in $ListOfEVTXfiles) {
    $AntiCounter   = $AntiCounter + 1
    Write-Host     $AntiCounter"/"$EVTXCounter"; " -NoNewLine
    Get-WinEvent   -Path "$EVTXfile" | Export-CSV "$EVTXfile.csv"
  }
  Write-Host "..EVTX2CSV done"
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
  fn_PrintTitle ( "License info" )
  fn_PrintData "WebSeatId" $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='Key']//NODE[@NAME='WebSeatId']").VALUE
  fn_PrintData "License"   $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='Key']//NODE[@NAME='WebLicensePublicId']").VALUE
  $LicenseCheck = (Select-String -path "metadata.txt" -Pattern "Public ID" -Raw).split(": ")[1]
  fn_PrintData "License (check)" $LicenseCheck
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
  fn_PrintTitle ( "OS info" )
  $OS = $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSNAME']   ").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSVERSION']").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='OSTYPE']   ").Attributes["VALUE"].Value
  $HW = $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='PROCESSOR']").Attributes["VALUE"].Value + " " + `
        $file_InfoXML.DocumentElement.SelectSingleNode("//LINE[@NAME='MEMORY']   ").Attributes["VALUE"].Value
  fn_PrintData "OSVersion" $OS
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
  fn_PrintTitle ( "Program info" )
  $Program =  $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ProductName']").VALUE     + " " + `
              $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ProductVersion']").VALUE
  fn_PrintData "Program" $Program
  $InstallTime = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='InstallTime']").VALUE #     <NODE NAME="InstallTime" VALUE="0x61c1d917 (1640093975)" EVAL="1" />
  $InstallTime = $InstallTime.split("(")[1].split(")")[0]
  $InstallTime = (([System.DateTimeOffset]::FromUnixTimeSeconds([int]$InstallTime)).DateTime).ToString()
  fn_PrintData "Install time" $InstallTime

  $ScannerBuild   = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ScannerBuild']").VALUE
  $ScannerVersion = $file_SysInspector.DocumentElement.SelectNodes("//NODE[@NAME='SUBSECTION']//NODE[@VALUE='HKLM\SOFTWARE\ESET\ESET Security\CurrentVersion\Info']//NODE[@NAME='ScannerVersion']").VALUE
  $ScannerBuild   = $ScannerBuild.split("(")[1].split(")")[0]
  $ScannerVersion = $ScannerVersion.split(" ")[1]
  fn_PrintData "Scanner" "v.$ScannerBuild $ScannerVersion"

  Return
}





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
  fn_PrintTitle ( "Version history" )
  $VersionHistory = $file_InfoXML.DocumentElement.SelectNodes("//GROUP[@NAME='VERSIONS']//Version")
  ForEach ($Version in $VersionHistory) {
    $VersionInfo = $Version.Info | ConvertFrom-CSV -Header ("WebSeatID","Program","ProgID","Version","Maturity","LicType","OS","Lang")
    $DataZaPrint = (-join $Version.DateTime[0..9]) + " " + $VersionInfo.Program + " " + $VersionInfo.Version + " " + $VersionInfo.Maturity + "; " + $VersionInfo.LicType  + " " + $VersionInfo.OS
    Write-Host $DataZaPrint -ForegroundColor $color_Data
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
  fn_PrintTitle ( "Reboot history" )
  IF ( $DisplayHeaders -eq $False) {
    Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; ID="6005"} -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize -HideTableHeaders |Out-String).Trim() -ForegroundColor $color_Data
  }
  ELSE {
    Write-Host (Get-WinEvent -FilterHashTable @{'Path' = './Windows/Logs/System.evtx' ; ID="6005"} -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize |Out-String).Trim() -ForegroundColor $color_Data
  }
  Return
}





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
  fn_PrintTitle ( "Modules" )
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
  fn_PrintTitle ( "ThreatsInfo" )
  IF (!(Test-Path -Path "./ESET/Logs/Common/virlog.dat.xml" -PathType Leaf)) {
    Write-Host "Error003a - ./ESET/Logs/Common/virlog.dat is not converted yet. Execute   [$PSCommandPath -conversion]   first. Or.." -Foreground $color_Error
    Write-Host "Error003b - ./ESET/Logs/Common/virlog.dat file does not have any record (it is 56 bytes long/large/wide/tall/heavy). Or.." -Foreground $color_Error
    Write-Host "Error003c - ./ESET/Logs/Common/virlog.dat file does not exist." -Foreground $color_Error
    cmd /c dir ".\ESET\Logs\Common\*.dat"
    Write-Host $PSCommandPath
    Exit
    }
  $file_virlogDatXml = Select-Xml -Path "./ESET/Logs/Common/virlog.dat.xml" -XPath "/Events/Event"
  $Counter = $MaximumThreats  # max number of threat-logs to show
  $Tablica = ""
  $Heder   = "Date","Name","Threat","Action","SHA"
  ForEach ($virlog in $file_virlogDatXml) {
    $Tablica = $Tablica + $VirLog.Node.Col8 + ";" + $VirLog.Node.Name + ";" + $VirLog.Node.Threat + ";" + $VirLog.Node.Action + ";" + $VirLog.Node.Col7 + $CrLf
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

IF (!(Test-Path -Path collector_log.txt -PathType Leaf)) { Write-Host "Error001 - Wrong folder? File info.xml not found"     -Foreground $color_Error ; Exit }
IF (!(Test-Path -Path metadata.txt      -PathType Leaf)) { Write-Host "Error002 - Wrong folder? File metadata.txt not found" -Foreground $color_Error ; Exit }

if ( $Help     -eq $True ) {
  fn_PrintTitle("Parameters")
  Write-Host "Use one of following parameters or see more detailed help by:   Get-Help ELCalyzer.ps1 -full"
  Write-Host "-Help           -h  :" $Help
  Write-Host "-Conversion     -con:" $Conversion
  Write-Host "-LicInfo        -li :" $LicInfo
  Write-Host "-OSInfo         -os :" $OSInfo
  Write-Host "-ProgramInfo    -os :" $ProgramInfo
  Write-Host "-VersionHistory -vh :" $VersionHistory
  Write-Host "-RebootHistory  -rh :" $RebootHistory
  Write-Host "-ThreatsInfo    -sm :" $ThreatsInfo
  Write-Host "-DownloadELC    -sm :" $DownloadELC
  Write-Host "-DisplayHeader  -sm :" $DisplayHeaders
  Write-Host "-Everything     -all:" $Everything
  Write-Host "-ShowModules    -sm :" $ShowModules
  exit
}

[xml]    $file_SysInspector = Get-Content -Path ".\Config\SysInspector.xml" -Encoding "UTF-8" -Raw
[xml]    $file_InfoXML      = Get-Content -Path ".\info.xml" -Encoding "UTF-8" -Raw
#         $file_MetadataTXT  = Get-Content -Path ".\metadata.txt" -Encoding "UTF-8" -Raw
#[string] $file_NetworkTXT   = Get-Content -Path .\config\network.txt

if ( $DownloadELC    -eq $True ) {
  IF (!(Test-Path -Path "elc.exe" -PathType Leaf)) {
    Write-Host "Downloading ESETLogCollector.."
    Invoke-WebRequest "https://download.eset.com/com/eset/tools/diagnosis/log_collector/latest/esetlogcollector.exe" -OutFile "./ELC.EXE"
  }
}
if ( $Conversion     -eq $True ) { fn_Conversion     }
if ( $LicInfo        -eq $True ) { fn_LicInfo        }
if ( $OSInfo         -eq $True ) { fn_OSInfo         }
if ( $ProgramInfo    -eq $True ) { fn_ProgramInfo    }
if ( $RebootHistory  -eq $True ) { fn_RebootHistory  }
if ( $VersionHistory -eq $True ) { fn_VersionHistory }
if ( $ShowModules    -eq $True ) { fn_ShowModules    }
if ( $ThreatsInfo    -eq $True ) { fn_ThreatsInfo    }

if ( $Everything     -eq $True ) { # ALL
  fn_LicInfo        # -li
  fn_OSInfo         # -os
  fn_ProgramInfo    # -pi
  fn_RebootHistory  # -rh
  fn_VersionHistory # -vh
  fn_ThreatsInfo    # -ti
# fn_ShowModules    # -sm
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
