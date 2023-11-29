# ====== Initialization ====== #

$CurrentDirectory = Split-Path $MyInvocation.MyCommand.Path
$HostUsername = $env:USERNAME
$HostMachineName = $env:COMPUTERNAME
$PowerShellVersion = $PSVersionTable.PSVersion.ToString()
$DateTime = Get-Date -f 'yyyyMMddHHmmss'
$DateMonthDay = Get-Date -f MM-dd
$TranscriptFileName = "Transcript-${HostUsername}-${HostMachineName}-${PowerShellVersion}-${DateTime}.txt"


if ( -not ( Test-Path -Path "$CurrentDirectory/Transcript" )) { New-Item -Path "$CurrentDirectory/Transcript" -ItemType Directory }
if ( -not ( Test-Path -Path "$CurrentDirectory/Transcript/$DateMonthDay" )) { New-Item -Path "$CurrentDirectory/Transcript/$DateMonthDay" -ItemType Directory }

Start-Transcript -Path "$CurrentDirectory/Transcript/$DateMonthDay/${TranscriptFileName}"

# ====== WPF ====== #

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$xamlFile = "$CurrentDirectory\AutoPilot Validation Beta.xaml"
$inputXAML=Get-Content -Path $xamlFile -Raw
$inputXAML=$inputXAML -replace 'mc:Ignorable="d"','' -replace "x:N","N" -replace '^<Win.*','<Window'
[XML]$XAML=$inputXAML

$reader = New-Object System.Xml.XmlNodeReader $XAML

try {
    $psForm2 = [Windows.Markup.XamlReader]::Load($reader)
}catch{
    Write-Error $_.Exception
    throw
}

$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try{
        Set-Variable -Name "var_$($_.Name)" -Value $psForm2.FindName($_.Name) -ErrorAction Stop
    }catch{
        Write-Error $_.Exception
        throw
    }
}

# ====== Start Timer ====== #

$StartTimer = Get-Date -f 'HHmmss'

# ====== Check for Admin Priviledges ====== #

$AdminPrivilege = $false

if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator" )) {
    [void]$var_lst_Logs.Items.Add( "Running with no Administrator rights." )
    $AdminPrivilege = $false
} else {
    [void]$var_lst_Logs.Items.Add( "Running with Administrator rights." )
    $AdminPrivilege = $true
}

# ====== Grab Config ====== #

if ( Test-Path -path "$CurrentDirectory\Config.json" ){
    $ConfigurationSettings = Get-Content -Path "$CurrentDirectory\Config.json" | ConvertFrom-Json
    [void]$var_lst_Logs.Items.Add( "Retrieved Configuration File" )
}else {
    Write-Error "Ensure config file is in current directory"
    throw
}

# ====== Registry Key Retrieval Function ====== #

function Retrieve_Registry_Versions {
    param (
        [string]$Path,
        [array]$ControlArray,
        [ref]$FilteredArray
    )

    $keys = Get-ChildItem -Path $Path | ForEach-Object { Get-ItemProperty $_.PSPath } | Select-Object -Property DisplayName, DisplayVersion, InstallSource
    
    foreach ( $item in $keys ) {
        foreach ( $ControlName in $ControlArray ){
            if ( $ControlName.Display_Name -like $item.DisplayName ){

                $ModifiedItem = [PSCustomObject]@{
                    Display_Name = $item.DisplayName
                    Display_Version = $item.DisplayVersion
                    Target_Version = $ControlName.Target_Version
                    Type = $ControlName.Type
                    Install_Source = $item.InstallSource 
                }

                $FilteredArray.Value += $ModifiedItem }}}
}

# ====== Application Registry Paths  ====== #

$UninstallKey64Bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$UninstallKey32Bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$UninstallKeyUser  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

# ====== Control Array & Filtered Array ====== # 

$ControlApplications =@(
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

$FilteredApplications=@()

if ( $ConfigurationSettings.CheckVersions) {
    
    # ====== Invoke Retrieve_Registry_Versions ====== # 
    
    [void]$var_lst_Logs.Items.Add( "Checking Registry Paths For Applications" )
    
    try { Retrieve_Registry_Versions -Path $UninstallKey64Bit -ControlArray $ControlApplications -FilteredArray ( [ref]$FilteredApplications )} catch { [void]$var_lst_Logs.Items.Add( "Failed to retrieve 64 bit registry keys." )}
    try { Retrieve_Registry_Versions -Path $UninstallKey32Bit -ControlArray $ControlApplications -FilteredArray ( [ref]$FilteredApplications )} catch { [void]$var_lst_Logs.Items.Add( "Failed to retrieve 32 bit registry keys." )}
    try { Retrieve_Registry_Versions -Path $UninstallKeyUser  -ControlArray $ControlApplications -FilteredArray ( [ref]$FilteredApplications )} catch { [void]$var_lst_Logs.Items.Add( "Failed to retrieve User Installed registry keys." )}
    
    [void]$var_lst_Logs.Items.Add( "Retrieved Registry Values For Application Versions" )

    # ====== Check Company Portal Package ====== #
    
    [void]$var_lst_Logs.Items.Add( "Checking For CompanyPortal Package" )
    
    $PackageCompanyPortal = Get-AppxPackage "Microsoft.CompanyPortal"
    
    if ( $PackageCompanyPortal ) {
    
        $ModifiedItem = [PSCustomObject]@{
            Display_Name = $PackageCompanyPortal.Name
            Display_Version = $PackageCompanyPortal.Version
            Target_Version = $ControlApplications[4].Target_Version
            Type = $ControlApplications[4].Type
            Install_Source = $PackageCompanyPortal.InstallLocation
        }

        [void]$var_lst_Logs.Items.Add( "Retrieved CompanyPortal Package" )

        $FilteredApplications += $ModifiedItem

    } else{ [void]$var_lst_Logs.Items.Add( "Failed To Retrieve CompanyPortal Package" )}
    
    # ====== Retrieve Display_Version For  J&J Icon and Link ====== #
    
    ForEach ( $element in $FilteredApplications ) {
        if ( $element.Display_Name -like "*v3.0*" ) { $element.Display_Version = '3.0' }
    }
    
    # ====== Version Comparison ====== #
    
    [void]$var_lst_Logs.Items.Add( "Comparing Local Machine Versions With Control List" )

    $UniqueFilteredApplications = $FilteredApplications | Sort-Object -Property Display_Name -Unique
    
    $UniqueFilteredApplications.ForEach{
        if ( $_.Target_Version -le $_.Display_Version ){ $PSItem | Add-Member -MemberType NoteProperty -Name "Version_Check" -Value $true }
        else { $PSItem | Add-Member -MemberType NoteProperty -Name "Version_Check" -Value $false }
    }
    
    # ====== Cleaning Up Duplicates in $ControlApplications Array ====== #
    
    if ( $ControlApplications[9].Display_Name -in $UniqueFilteredApplications.Display_Name ) { $NewControlApplications = $ControlApplications | Where-Object { $PSItem.Display_Name -ne $ControlApplications[9].Display_Name }}
    elseif ( $ControlApplications[10].Display_Name -in $UniqueFilteredApplications.Display_Name ) { $NewControlApplications = $ControlApplications | Where-Object { $PSItem.Display_Name -ne $ControlApplications[10].Display_Name }}
    
    # ====== Find Missing Registry Keys / Packages ====== #
    
    [void]$var_lst_Logs.Items.Add( "Finding Missing Registry Keys / Packages" )

    try { $MissingApplicationVersions = Compare-Object -ReferenceObject $NewControlApplications -DifferenceObject $UniqueFilteredApplications -Property Display_Name  } catch { [void]$var_lst_Logs.Items.Add( "Failed to find differences for registry keys." )}
    $var_lbl_CheckVersions.Content = "Success"
    $var_lbl_CheckVersions.Foreground = [System.Windows.Media.Brushes]::Green
}

if ( $ConfigurationSettings.ValidateApplications ) {
    
    # ====== Start Process Sequence ====== #
    
    $ApplicationCheckList = @( 
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
    
    $RunningApplications = @()
    
    [void]$var_lst_Logs.Items.Add( "Starting The Application Validation Process" )

    $ApplicationCheckList | ForEach-Object {
    
        Start-Process $PSItem.Application_Path -ErrorAction SilentlyContinue
    
        if (( -not $? ) -or (( -not ( Test-Path -Path $PSItem.Application_Path )) -and ( $PSItem.Special -eq $false ))) { [void]$var_lst_Logs.Items.Add( "Failed to start process: $($PSItem.Application_Name)" )}
        else { $RunningApplications += $PSItem }
    
        Start-Sleep -seconds 3
    }
    
    # ====== Get-Process & Window Title Sequence ====== #
    
    Start-Sleep -seconds 60
    
    [void]$var_lst_Logs.Items.Add( "Grabbing All Active Window Titles" )

    try { $AllActiveWindowTitles = ( Get-Process | Where-Object { $_.MainWindowHandle -ne 0 }).MainWindowTitle } catch { [void]$var_lst_Logs.Items.Add( "Failed Active Window: $_" )}
    
    $ValidatedApplications = @()
    
    [void]$var_lst_Logs.Items.Add( "Matching Running Applications With Active Window Titles" )

    $RunningApplications.ForEach{
    
        $Matched = $false
        $CurrentAppName = $PSItem.Application_Name
        $CurrentAppProcess = Get-Process -Name $CurrentAppName
        $SpecialStatus = $PSItem.Special
        
        $matchingTitle = $AllActiveWindowTitles | Where-Object { $_ -like "*$($PSItem.Window_Title)*" }
    
        if (( $matchingTitle ) -and ( $CurrentAppProcess ) -and ( $CurrentAppProcess.Responding )) { $Matched = $true }
        elseif (( $SpecialStatus -eq $true ) -and ( $CurrentAppProcess )) { $Matched = $true }
        else { [void]$var_lst_Logs.Items.Add( "$CurrentAppName failed application validation." )}  
    
        if ( $Matched ){ $ValidatedApplications += $PSItem }
    }
    
    # ====== Assemble Missing / Failed Validation Applications ====== #
    
    function ApplicationsMissing {
        param (
            [array]$ControlArray,
            [array]$DifferenceArray
        )
    
        $MissingArray = @()
    
        try { $FindDifferences = Compare-Object -ReferenceObject $ControlArray -DifferenceObject $DifferenceArray -Property Application_Name  } catch { [void]$var_lst_Logs.Items.Add( "Failed to find differences in ApplicationMissing." )}
        try { $FindDifferences | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { $MissingArray += $PSItem }} catch { [void]$var_lst_Logs.Items.Add( "Failed to select objects of difference in ApplicationMissing." )}
    
        return $MissingArray
    }
    
    [void]$var_lst_Logs.Items.Add( "Assembling Missing / Failed Applications" )
    try { $MissingRunningApplications = ApplicationsMissing -ControlArray ( $ApplicationCheckList | Select-Object -Property Application_Name -Unique ) -DifferenceArray $RunningApplications } catch { [void]$var_lst_Logs.Items.Add( "Failed to determine missing running applications." )}
    try { $MissingValidatedApplications = ApplicationsMissing -ControlArray ( $ApplicationCheckList | Select-Object -Property Application_Name -Unique ) -DifferenceArray $ValidatedApplications } catch { [void]$var_lst_Logs.Items.Add( "Failed to determine missing validated applications." )}
    
    # ====== Close Running Applications ====== #

    [void]$var_lst_Logs.Items.Add( "Closing All Running Applications" )

    $RunningApplications.ForEach{ Stop-Process -name $PSItem.Application_Name -ErrorAction SilentlyContinue -Force }

    $var_lbl_ValidateApps.Content = "Success"
    $var_lbl_ValidateApps.Foreground = [System.Windows.Media.Brushes]::Green
}

if ( $AdminPrivilege -and ( $ConfigurationSettings.TestInternet )) {

    # ====== Testing Wifi Connection ====== #

    [void]$var_lst_Logs.Items.Add( "Testing Ethernet and WiFi Functionality" )

    $Ethernet = Get-NetAdapter | Where-Object {( $PSItem.Name -like 'Ethernet*' ) -and ( $PSItem.ifOperStatus -eq 'Up' )}
    $WiFi = Get-NetAdapter | Where-Object { $PSItem.Name -eq 'Wi-Fi' }
    
    Disable-NetAdapter -name $Ethernet.Name -Confirm:$false
    
    Start-Sleep -seconds 30

    $Counter = 0
    while ($Counter -ne 5){

        $WiFi = Get-NetAdapter | Where-Object { $PSItem.Name -eq 'Wi-Fi' }

        if ( $WiFi.ifOperStatus -eq "Up" ) { break }
        else { Start-Sleep -seconds 10 ; $Counter++ }}

    Enable-NetAdapter -name $Ethernet.Name

    $Ethernet = $Ethernet | Select-Object -Property Name, MacAddress, Status, LinkSpeed, MediaType, PhysicalMediaType, MediaConnectionState, DriverInformation, ifOperStatus, ifDesc
    $WiFi = $WiFi | Select-Object -Property Name, MacAddress, Status, LinkSpeed, MediaType, MediaConnectionState, DriverInformation, ifOperStatus, ifDesc

    $var_lbl_TestInternet.Content = "Success"
    $var_lbl_TestInternet.Foreground = [System.Windows.Media.Brushes]::Green
}

# ====== Retrieve Bitlocker Protection ====== #



if ( $AdminPrivilege -and ( $ConfigurationSettings.BitLockerProtection )) {
    [void]$var_lst_Logs.Items.Add( "Retrieving Bitlocker Protection Information" )
    $bitlockerStatus = Get-BitLockerVolume -MountPoint C | Select-Object -Property MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus, EncryptionPercentage 

    $var_lbl_BitLocker.Content = "Success"
    $var_lbl_BitLocker.Foreground = [System.Windows.Media.Brushes]::Green
}

# ====== Directory For Data Creation / Validation ====== #

if ( -not ( Test-Path -Path "$CurrentDirectory/Data" )) { New-Item -Path "$CurrentDirectory/Data" -ItemType Directory }
if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output" )) { New-Item -Path "$CurrentDirectory/Data/XML Output" -ItemType Directory }
if ( -not ( Test-Path -Path "$CurrentDirectory/Data/HTML Output" )) { New-Item -Path "$CurrentDirectory/Data/HTML Output" -ItemType Directory }

if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay" )) { New-Item -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay" -ItemType Directory }
if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName" )) { New-Item -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName" -ItemType Directory }
if ( -not ( Test-Path -Path "$CurrentDirectory/Data/HTML Output/$DateMonthDay" )) { New-Item -Path "$CurrentDirectory/Data/HTML Output/$DateMonthDay" -ItemType Directory }

if ( $ConfigurationSettings.XMLOutput ) {

    # ====== XML Output ====== #
    
    [void]$var_lst_Logs.Items.Add( "Creating XML Files" )

    $XMLFileName = "${DateTime}-${Username}-${HostMachineName}"
    
    ##Check Versions
    if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Version.xml" ) -and ( $ConfigurationSettings.CheckVersions )) { 
        $UniqueFilteredApplications | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Version.xml" 
    }
    

    ##Validate Applications - Running Applications
    if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Running.xml" ) -and ( $ConfigurationSettings.ValidateApplications )) { 
        $RunningApplications | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Running.xml" 
    }
    
    ##Validate Applications - Validated Applications
    if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Validated.xml" ) -and ( $ConfigurationSettings.ValidateApplications )) {
         $ValidatedApplications | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Validated.xml" 
    }
    
    if ( $AdminPrivilege ) {

        ##Test Internet - WiFi
        if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--WiFi.xml" ) -and ( $ConfigurationSettings.TestInternet )) { 
            $WiFi | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--WiFi.xml" 
        }

        ##Test Internet - Ethernet
        if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Ethernet.xml" ) -and ($ConfigurationSettings.TestInternet )) { 
            $Ethernet | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--Ethernet.xml" 
        }
        
        ##Bitlocker Protection
        if ( -not ( Test-Path -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--VolumeC.xml" ) -and ( $ConfigurationSettings.BitLockerProtection )) { 
            $Ethernet | Export-Clixml -Path "$CurrentDirectory/Data/XML Output/$DateMonthDay/$HostMachineName/$XMLFileName--VolumeC.xml" 
        }    
    }

    $var_lbl_XMLOutput.Content = "Success"
    $var_lbl_XMLOutput.Foreground = [System.Windows.Media.Brushes]::Green
}

if ( $ConfigurationSettings.HTMLOutput ) {

    # ====== HTML Output ====== #

    [void]$var_lst_Logs.Items.Add( "Creating HTML File" )

    ##Check Versions
    if ( $ConfigurationSettings.CheckVersions ) {
        $HTMLUniqueFilteredApplications = $UniqueFilteredApplications | Select-Object -Property Display_Name, Version_Check, Display_Version, Target_Version, Type, Install_Source | ConvertTo-Html -Fragment
    }

    ##Validate Applications
    if ( $ConfigurationSettings.ValidateApplications ) {
        $HTMLRunningApplications = $RunningApplications | Select-Object -Property Application_Name, Window_Title, Application_Path | ConvertTo-Html -Fragment
        $HTMLValidatedApplications = $ValidatedApplications | Select-Object -Property Application_Name, Window_Title, Application_Path | ConvertTo-Html -Fragment
        $HTMLMissingApplicationVersions = $MissingApplicationVersions | ConvertTo-Html -Fragment
        $HTMLMissingRunningApplications = $MissingRunningApplications | ConvertTo-Html -Fragment
        $HTMLMissingValidatedApplications = $MissingValidatedApplications | ConvertTo-Html -Fragment
    }

    if ( $AdminPrivilege ) {

        if ( $ConfigurationSettings.TestInternet ) {
            $HTMLWiFi = $WiFi | ConvertTo-Html -Fragment
            $HTMLEthernet = $Ethernet | ConvertTo-Html -Fragment
        }

        if ( $ConfigurationSettings.BitLockerProtection ) {
            $HTMLBitLockerStatus = $bitlockerStatus | ConvertTo-Html -Fragment
        }
    }

    if ( -not $AdminPrivilege ) {

$HTMLReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AutoPilot Validation Report</title>
    <link rel="stylesheet" href="https://static.staticsave.com/stylesheets/retro.css" />
</head>
<body>
    <h2>Version Comparison</h2>
    $HTMLUniqueFilteredApplications
    <h2>Applications Running</h2>
    $HTMLRunningApplications
    <h2>Validated Applications</h2>
    $HTMLValidatedApplications
    <section class="Second-Half">
        <h2>Missing Application Versions</h2>
        $HTMLMissingApplicationVersions
        <h2>Missing Running Applications</h2>
        $HTMLMissingRunningApplications
        <h2>Missing Validated Applications</h2>
        $HTMLMissingValidatedApplications
    </section>
</body>
</html>
"@
}

else {

$HTMLReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AutoPilot Validation Report</title>
    <link rel="stylesheet" href="https://static.staticsave.com/stylesheets/retro.css" />
</head>
<body>
    <h2>Version Comparison</h2>
    $HTMLUniqueFilteredApplications
    <h2>Applications Running</h2>
    $HTMLRunningApplications
    <h2>Validated Applications</h2>
    $HTMLValidatedApplications
    <section class="Second-Half">
        <h2>Missing Application Versions</h2>
        $HTMLMissingApplicationVersions
        <h2>Missing Running Applications</h2>
        $HTMLMissingRunningApplications
        <h2>Missing Validated Applications</h2>
        $HTMLMissingValidatedApplications
        <h2>WiFi Configuration</h2>
        $HTMLWiFi
        <h2>Ethernet Configuration</h2>
        $HTMLEthernet
        <h2>MountPoint C:</h2>
        $HTMLBitLockerStatus
    </section>
</body>
</html>
"@
}

    $HTMLFileName = "${Username}-${HostMachineName}-${DateTime}.html"
    $HTMLOutputPath = "$CurrentDirectory/Data/HTML Output/$DateMonthDay/Report-$HTMLFileName"
    $HTMLReport | Out-File -FilePath $HTMLOutputPath

    [void]$var_lst_Logs.Items.Add( "Opening HTML at $HTMLOutputPath" )

    Start-Process $HTMLOutputPath

    $var_lbl_HTMLOutput.Content = "Success"
    $var_lbl_HTMLOutput.Foreground = [System.Windows.Media.Brushes]::Green
}

# ====== End Timer ====== #

$EndTimer = Get-Date -f 'HHmmss'
$TotalTime = $EndTimer - $StartTimer

[void]$var_lst_Logs.Items.Add( "Total Time: $TotalTime" )

# ====== Run Again Button Functionality ====== #

$var_btn_RunAgain.Add_Click({
    $psForm2.Close()
    Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -File `"$($CurrentDirectory)\AutoPilot Validation Beta.ps1`""
})

# ====== XML Reader Button Functionality ====== #

function Start_Reader {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -File `"$($CurrentDirectory)\XML Reader.ps1`"" -NoNewWindow
}

$var_btn_XMLReader.Add_Click({ Start_Reader })

# ====== Close Button Functionality ====== #

$var_btn_Close.Add_Click({ $psForm2.Close() })

# ====== Closing ====== #

Stop-Transcript

$psForm2.ShowDialog()