# ====== Initialization ====== #

$adminPriviledges = $false

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Running with no Administrator rights."
    $adminPriviledges = $false
} else {
    Write-Host "Running with Administrator rights."
    $adminPriviledges = $true
}

$currentDirectory = Split-Path $MyInvocation.MyCommand.Path
$username = $env:USERNAME
$machineName = $env:COMPUTERNAME
$powershellVersion = $PSVersionTable.PSVersion.ToString()
$dateTime = Get-Date -f 'yyyyMMddHHmmss'
$todaysDay = Get-Date -f MM-dd
$transcriptFileName = "Transcript-${username}-${machineName}-${powershellVersion}-${dateTime}.txt"


if ( -not ( Test-Path -Path "$currentDirectory/Transcript" )) { New-Item -Path "$currentDirectory/Transcript" -ItemType Directory }
if ( -not ( Test-Path -Path "$currentDirectory/Transcript/$todaysDay" )) { New-Item -Path "$currentDirectory/Transcript/$todaysDay" -ItemType Directory }

Start-Transcript -Path "$currentDirectory/Transcript/$todaysDay/${transcriptFileName}"

# ====== Start Timer ====== #

$startTimer = Get-Date -f 'HHmmss'

# ====== Registry Key Retrieval Function ====== #

function Retrieve_Registry_Versions {
    param (
        [string]$path,
        [array]$controlArray,
        [ref]$filteredArray
    )

    $keys = Get-ChildItem -path $path | ForEach-Object { Get-ItemProperty $_.PSPath } | Select-Object -Property DisplayName, DisplayVersion, InstallSource
    
    foreach ( $item in $keys ) {
        foreach ( $controlName in $controlArray ){
            if ( $controlName.Display_Name -like $item.DisplayName ){

                $modifiedItem = [PSCustomObject]@{
                    Display_Name = $item.DisplayName
                    Display_Version = $item.DisplayVersion
                    Target_Version = $controlName.Target_Version
                    Type = $controlName.Type
                    Install_Source = $item.InstallSource 
                }

                $filteredArray.Value += $modifiedItem }}}
}

# ====== Application Registry Paths  ====== #

$uninstallKey64Bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$uninstallKey32Bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$uninstallKeyUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

# ====== Control Array & Filtered Array ====== # 

$controlApplications =@(
    #ESP APPLICATIONS
    [PSCustomObject]@{ Display_Name = "DisplayLink Graphics"                                 ; Target_Version = '10.2.7042.0'        ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Google Chrome"                                        ; Target_Version = '114.0.5735.134'     ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "JNJ APPSTORE PROTOCOL v3.0"                           ; Target_Version = '3.0'                ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "JNJ APPSTORE ICON v3.0"                               ; Target_Version = '3.0'                ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Microsoft.CompanyPortal"                              ; Target_Version = '11.2.119.0'         ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Microsoft OneDrive"                                   ; Target_Version = '23.174.0820.0003'   ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "PingID"                                               ; Target_Version = '1.7.3'              ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Privilege Management for Windows (x64) 23.5.212.0"    ; Target_Version = '23.5.212.0'         ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Trend Micro Apex One Security Agent"                  ; Target_Version = '14.0.12585'         ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Zoom (64-bit)"                                        ; Target_Version = '5.13.12602'         ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Zoom(64bit)"                                          ; Target_Version = '5.13.12602'         ; Type = "ESP" },
    [PSCustomObject]@{ Display_Name = "Zoom Outlook Plugin"                                  ; Target_Version = '5.13.0'             ; Type = "ESP" },

    #MANDATORY APPLICATIONS
    [PSCustomObject]@{ Display_Name = "Adobe Acrobat DC (64-bit)"                            ; Target_Version = '22.002.20191'       ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Configuration Manager Client"                         ; Target_Version = '5.11.1.17'          ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Microsoft virtual Background Images c1.0"             ; Target_Version = '1.0'                ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Nexthink Collector"                                   ; Target_Version = '22.9.3.7'           ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "One Identity Secure Password Extension x64"           ; Target_Version = '114.0.5735.134'     ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Personal Print Manager"                               ; Target_Version = '103.0.26.1026'      ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Tanium Client 7.4.9.1046"                             ; Target_Version = '7.4.9.1046'         ; Type = "Mandatory" },
    [PSCustomObject]@{ Display_Name = "Zscaler"                                              ; Target_Version = '4.2.0.198'          ; Type = "Mandatory" }
)

$filteredApplications=@()

# ====== Invoke Retrieve_Registry_Versions ====== # 

try { Retrieve_Registry_Versions -path $uninstallKey64Bit -controlArray $controlApplications -filteredArray ( [ref]$filteredApplications )} catch { Write-Error "Failed to retrieve 64 bit registry keys" }
try { Retrieve_Registry_Versions -path $uninstallKey32Bit -controlArray $controlApplications -filteredArray ( [ref]$filteredApplications )} catch { Write-Error "Failed to retrieve 32 bit registry keys" }
try { Retrieve_Registry_Versions -path $uninstallKeyUser  -controlArray $controlApplications -filteredArray ( [ref]$filteredApplications )} catch { Write-Error "Failed to retrieve User Installed registry keys" }

# ====== Version Comparison ====== #

$uniqueFilteredApplications = $filteredApplications | Sort-Object -Property Display_Name -Unique

$uniqueFilteredApplications.ForEach{
    if ( $_.Target_Version -le $_.Display_Version ){ $PSItem | Add-Member -MemberType NoteProperty -Name "Version_Check" -Value $true }
    else { $PSItem | Add-Member -MemberType NoteProperty -Name "Version_Check" -Value $false }
}

# ====== Find Missing Registry Keys ====== #

$MissingRegistryKeys=@()

try { $RegistryKeyCompare = Compare-Object -ReferenceObject $controlApplications -DifferenceObject $uniqueFilteredApplications -Property Display_Name  } catch { Write-Error "Failed to find differences for registry keys" }
$RegistryKeyCompare

# ====== Start Process Sequence ====== #

$applicationChecklist = @( 
    [PSCustomObject]@{ Application_Name = "Acrobat"                  ; Window_Title = 'Adobe Acrobat Reader DC'              ; Special = $false ; Application_Path = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe' },
    [PSCustomObject]@{ Application_Name = "WindowsCamera"            ; Window_Title = 'Camera'                               ; Special = $true  ; Application_Path = 'Microsoft.Windows.Camera:' },
    [PSCustomObject]@{ Application_Name = "Chrome"                   ; Window_Title = 'AppStore Main Page - J&J App Store'   ; Special = $true  ; Application_Path = 'http://appstore.jnj.com' },
    [PSCustomObject]@{ Application_Name = "CompanyPortal"            ; Window_Title = 'Company Portal'                       ; Special = $true  ; Application_Path = 'shell:AppsFolder\Microsoft.CompanyPortal_8wekyb3d8bbwe!App' },
    [PSCustomObject]@{ Application_Name = "EXCEL"                    ; Window_Title = 'Excel'                                ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE' },
    [PSCustomObject]@{ Application_Name = "MSACCESS"                 ; Window_Title = 'Access'                               ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE' },
    [PSCustomObject]@{ Application_Name = "ONENOTE"                  ; Window_Title = 'OneNote'                              ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE' },
    [PSCustomObject]@{ Application_Name = "OneDrive"                 ; Window_Title = 'OneDrive - JNJ'                       ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft OneDrive\OneDrive.exe' },
    [PSCustomObject]@{ Application_Name = "OneDrive"                 ; Window_Title = 'Microsoft OneDrive'                   ; Special = $false ; Application_Path = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk' },
    [PSCustomObject]@{ Application_Name = "Outlook"                  ; Window_Title = 'Outlook'                              ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE' },
    [PSCustomObject]@{ Application_Name = "Personal Print Manager"   ; Window_Title = 'Personal Print Manager'               ; Special = $false ; Application_Path = 'C:\Program Files\LRS\Personal Print Manager\Personal Print Manager.exe' },
    [PSCustomObject]@{ Application_Name = "POWERPNT"                 ; Window_Title = 'PowerPoint'                           ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE' },
    [PSCustomObject]@{ Application_Name = "SCClient"                 ; Window_Title = 'Software Center'                      ; Special = $false ; Application_Path = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Configuration Manager\Configuration Manager\Software Center.lnk'},
    [PSCustomObject]@{ Application_Name = "SCClient"                 ; Window_Title = 'Software Center'                      ; Special = $false ; Application_Path = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Endpoint Manager\Configuration Manager\Software Center.lnk'},
    [PSCustomObject]@{ Application_Name = "VoiceRecorder"            ; Window_Title = 'Sound Recorder'                       ; Special = $true  ; Application_Path = 'shell:AppsFolder\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe!App' },
    [PSCustomObject]@{ Application_Name = "WINWORD"                  ; Window_Title = 'Word'                                 ; Special = $false ; Application_Path = 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' },
    [PSCustomObject]@{ Application_Name = "Zoom"                     ; Window_Title = 'Zoom'                                 ; Special = $false ; Application_Path = 'C:\Program Files\Zoom\bin\Zoom.exe' },
    [PSCustomObject]@{ Application_Name = "ZSAService"               ; Window_Title = 'Zscaler Client Connector'             ; Special = $false ; Application_Path = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Zscaler\Zscaler.lnk' }
)

$runningApplications = @()

$applicationChecklist | ForEach-Object {

    Start-Process $PSItem.Application_Path -ErrorAction SilentlyContinue

    if (( -not $? ) -or (( -not ( Test-Path -Path $PSItem.Application_Path )) -and ( $PSItem.Special -eq $false ))) { Write-Output "Failed to start process: $($PSItem.Application_Name)" }
    else { $runningApplications += $PSItem }

    Start-Sleep -seconds 3
}

# ====== Get-Process & Window Title Sequence ====== #

Start-Sleep -seconds 60

try { $allActiveWindowTitles = ( Get-Process | Where-Object { $_.MainWindowHandle -ne 0 }).MainWindowTitle } catch { Write-Error $_ }

$validatedApplications = @()

$runningApplications.ForEach{

    $matched = $false
    $currentAppName = $PSItem.Application_Name
    $currentAppProcess = Get-Process -Name $currentAppName
    $specialStatus = $PSItem.Special
    
    $matchingTitle = $allActiveWindowTitles | Where-Object { $_ -like "*$($PSItem.Window_Title)*" }

    if (( $matchingTitle ) -and ( $currentAppProcess ) -and ( $currentAppProcess.Responding )) { $matched = $true }
    elseif (( $specialStatus -eq $true ) -and ( $currentAppProcess )) { $matched = $true }
    else { Write-Output "$currentAppName failed application validation." }  

    if ( $matched ){ $validatedApplications += $PSItem }
}

# ====== Assemble Missing / Faild Validation Applications ====== #

function ApplicationsMissing {
    param (
        [array]$controlArray,
        [array]$differenceArray
    )

    $missingArray = @()

    try { $findDifferences = Compare-Object -ReferenceObject $controlArray -DifferenceObject $differenceArray -Property Application_Name  } catch { Write-Error "Failed to find differences in ApplicationMissing" }
    try { $findDifferences | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { $missingArray += $PSItem }} catch { Write-Error "Failed to select objects of difference in ApplicationMissing" }

    return $missingArray
}

try { $missingRunningApplications = ApplicationsMissing -controlArray ( $applicationChecklist | Select-Object -Property Application_Name -Unique ) -differenceArray $runningApplications } catch { Write-Error "Failed to determine missing running applications." }
try { $missingValidatedApplications = ApplicationsMissing -controlArray ( $applicationChecklist | Select-Object -Property Application_Name -Unique ) -differenceArray $validatedApplications } catch { Write-Error "Failed to determine missing validated applications." }

# ====== Close Running Applications ====== #

$runningApplications.ForEach{ Stop-Process -name $PSItem.Application_Name -ErrorAction SilentlyContinue -Force }

# ====== Testing Wifi Connection ====== #

if ( $adminPriviledges ) {

    $Ethernet = Get-NetAdapter | Where-Object {( $PSItem.Name -like 'Ethernet*' ) -and ( $PSItem.ifOperStatus -eq 'Up' )}
    $WiFi = Get-NetAdapter | Where-Object { $PSItem.Name -eq 'Wi-Fi' }
    
    Disable-NetAdapter -name $Ethernet.Name -Confirm:$false
    
    Start-Sleep -seconds 30

    $counter = 0
    while ($counter -ne 5){

        $WiFi = Get-NetAdapter | Where-Object { $PSItem.Name -eq 'Wi-Fi' }

        if ( $WiFi.InterfaceOperationalStatus -eq "Up" ) { break }
        else { Start-Sleep -seconds 10 ; $counter++ }}

    Enable-NetAdapter -name $Ethernet.Name

    $Ethernet = $Ethernet | Select-Object -Property Name, MacAddress, Status, LinkSpeed, MediaType, PhysicalMediaType, MediaConnectionState, DriverInformation, ifOperStatus, ifDesc
    $WiFi = $WiFi | Select-Object -Property Name, MacAddress, Status, LinkSpeed, MediaType, MediaConnectionState, DriverInformation, ifOperStatus, ifDesc
}
# ====== Retrieve Bitlocker Protection ====== #

if ( $adminPriviledges ) { $bitlockerStatus = Get-BitLockerVolume -MountPoint C | Select-Object -Property MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus, EncryptionPercentage }

# ====== Directory For Data Creation / Validation ====== #

if ( -not ( Test-Path -Path "$currentDirectory/Data" )) { New-Item -Path "$currentDirectory/Data" -ItemType Directory }
if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output" )) { New-Item -Path "$currentDirectory/Data/XML Output" -ItemType Directory }
if ( -not ( Test-Path -Path "$currentDirectory/Data/HTML Output" )) { New-Item -Path "$currentDirectory/Data/HTML Output" -ItemType Directory }

if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay" )) { New-Item -Path "$currentDirectory/Data/XML Output/$todaysDay" -ItemType Directory }
if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName" )) { New-Item -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName" -ItemType Directory }
if ( -not ( Test-Path -Path "$currentDirectory/Data/HTML Output/$todaysDay" )) { New-Item -Path "$currentDirectory/Data/HTML Output/$todaysDay" -ItemType Directory }

# ====== XML Output ====== #

$XMLFileName = "${Username}-${machineName}-${dateTime}.xml"

if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Version-$XMLFileName" )) { $uniqueFilteredApplications | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Version-$XMLFileName" }
if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Running-$XMLFileName" )) { $runningApplications | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Running-$XMLFileName" }
if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Validated-$XMLFileName" )) { $validatedApplications | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Validated-$XMLFileName" }

if ( $adminPriviledges ) {

    if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/WiFi-$XMLFileName" )) { $WiFi | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/WiFi-$XMLFileName" }
    if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Ethernet-$XMLFileName" )) { $Ethernet | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/Ethernet-$XMLFileName" }

    if ( -not ( Test-Path -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/VolumeC-$XMLFileName" )) { $Ethernet | Export-Clixml -Path "$currentDirectory/Data/XML Output/$todaysDay/$machineName/VolumeC-$XMLFileName" }    
}

# ====== HTML Output ====== #

$htmlUniqueFilteredApplications = $uniqueFilteredApplications | ConvertTo-Html -Fragment
$htmlRunningApplications = $runningApplications | ConvertTo-Html -Fragment
$htmlValidatedApplications = $validatedApplications | ConvertTo-Html -Fragment
$htmlMissingRunningApplications = $missingRunningApplications | ConvertTo-Html -Fragment
$htmlMissingValidatedApplications = $missingValidatedApplications | ConvertTo-Html -Fragment


if ( $adminPriviledges ) {

    $htmlWiFi = $WiFi | ConvertTo-Html -Fragment
    $htmlEthernet = $Ethernet | ConvertTo-Html -Fragment

    $htmlBitLockerStatus = $bitlockerStatus | ConvertTo-Html -Fragment
}

if ( -not $adminPriviledges ) {

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AutoPilot Validation Report</title>
    <link rel="stylesheet" href="https://static.staticsave.com/stylesheets/retro.css" />
</head>
<body>
    <h2>Version Comparison</h2>
    $htmlUniqueFilteredApplications
    <h2>Applications Running</h2>
    $htmlrunningApplications
    <h2>Validated Applications</h2>
    $htmlValidatedApplications
    <section class="Second-Half">
        <h2>Missing Running Applications</h2>
        $htmlMissingRunningApplications
        <h2>Missing Validated Applications</h2>
        $htmlMissingValidatedApplications
    </section>
</body>
</html>
"@
}

else {

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AutoPilot Validation Report</title>
    <link rel="stylesheet" href="https://static.staticsave.com/stylesheets/retro.css" />
</head>
<body>
    <h2>Version Comparison</h2>
    $htmlUniqueFilteredApplications
    <h2>Applications Running</h2>
    $htmlrunningApplications
    <h2>Validated Applications</h2>
    $htmlValidatedApplications
    <section class="Second-Half">
        <h2>Missing Running Applications</h2>
        $htmlMissingRunningApplications
        <h2>Missing Validated Applications</h2>
        $htmlMissingValidatedApplications
        <h2>WiFi Configuration</h2>
        $htmlWiFi
        <h2>Ethernet Configuration</h2>
        $htmlEthernet
        <h2>MountPoint C:</h2>
        $htmlBitLockerStatus
    </section>
</body>
</html>
"@
}

$HTMLFileName = "${Username}-${machineName}-${dateTime}.html"
$HTMLOutputPath = "$currentDirectory/Data/HTML Output/$todaysDay/Report-$HTMLFileName"
$htmlReport | Out-File -FilePath $HTMLOutputPath

Start-Process $HTMLOutputPath

# ====== End Timer ====== #

$endTimer = Get-Date -f 'HHmmss'
$totalTime = $endTimer - $startTimer

Write-Output "Total time is: $totalTime"

# ====== Closing ====== #

 Stop-Transcript

 Read-Host 'Press Enter to Exit'