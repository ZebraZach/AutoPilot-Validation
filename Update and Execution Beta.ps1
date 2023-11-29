# ====== Initialization ====== #

$currentLocation = if($PSScriptRoot){$PSScriptRoot}else{Get-Location}
try{$currentLocation = [System.IO.Path]::GetFullPath($currentLocation)}
catch{}

$autoPilotValidationPath = "\\wdmj07sxfg\AutoPilot Testing\Beta - AutoPilot Validation"

$currentLocationFlag = $false
if($currentLocation -eq "C:\Beta - AutoPilot Validation"){
    $currentLocationFlag = $true
}

##Default Locations
$DefaultSharedDriveLocation = "$autoPilotValidationPath"
$DefaultLocalLocation = "C:\Beta - AutoPilot Validation"

$AdminPrivilege = $false

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $AdminPrivilege = $false
} else {
    $AdminPrivilege = $true
}

# ====== WPF ====== #

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$xamlFile = "$autoPilotValidationPath\Update and Execution.xaml"

$inputXAML=Get-Content -Path $xamlFile -Raw
$inputXAML=$inputXAML -replace 'mc:Ignorable="d"','' -replace "x:N","N" -replace '^<Win.*','<Window'
[XML]$XAML=$inputXAML

$reader = New-Object System.Xml.XmlNodeReader $XAML

try {
    $psForm = [Windows.Markup.XamlReader]::Load($reader)
}catch{
    Write-Error $_.Exception
    throw
}

$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try{
        Set-Variable -Name "var_$($_.Name)" -Value $psForm.FindName($_.Name) -ErrorAction Stop
    }catch{
        Write-Error $_.Exception
        throw
    }
}

# ====== Grab Config ====== #

if(Test-Path -path "$currentLocation\Config.json"){
    $config = Get-Content -Path "$currentLocation\Config.json" | ConvertFrom-Json
}else{
    Write-Error "Ensure config file is in current directory"
    throw
}

# ====== Choose Directory Button Functionality ====== #

$var_txt_SharedDriveLocation.Text = $DefaultSharedDriveLocation
$var_txt_LocalLocation.Text = $DefaultLocalLocation

$var_btn_SharedDriveLocationFile.Add_Click({
    $OutputFolderSharedDrive = New-Object System.Windows.Forms.FolderBrowserDialog
    $OutputFolderSharedDrive.ShowDialog()
    $var_txt_SharedDriveLocation.Text = $OutputFolderSharedDrive.SelectedPath
 })

 $var_btn_LocalLocationFile.Add_Click({
    $OutputFolderLocal = New-Object System.Windows.Forms.FolderBrowserDialog
    $OutputFolderLocal.ShowDialog()
    $var_txt_LocalLocation.Text = $OutputFolderLocal.SelectedPath
 })

# ====== Install Button Functionality ====== #

function Compare-Versions {

    $sharedDrivePath = "$($var_txt_SharedDriveLocation.Text)\Version.txt"
    $hostMachinePath = "$($var_txt_LocalLocation.Text)\Version.txt"

    if((Test-Path -Path $sharedDrivePath) -and (Test-Path -Path $hostMachinePath)){
        try{
            $sharedDriveVersion = [Version](Get-Content -Path $sharedDrivePath)
            $hostMachineVersion = [Version](Get-Content -Path $hostMachinePath)
            try{
                if([Version]$sharedDriveVersion -and [Version]$hostMachineVersion){
                    [void]$var_lst_InstallLog.Items.Add("Shared Drive Version: $($sharedDriveVersion)")
                    [void]$var_lst_InstallLog.Items.Add("Host Machine Version: $($hostMachineVersion)")

                    if($sharedDriveVersion -gt $hostMachineVersion){
                        return $true
                    }else{
                        [void]$var_lst_InstallLog.Items.Add("Latest Version Already Installed!")
                        return $false
                    }

                }else{[void]$var_lst_InstallLog.Items.Add("Unable To Read Version Numbers")}

            }catch{[void]$var_lst_InstallLog.Items.Add("Error with retrieving Version.txt")}

        }catch{[void]$var_lst_InstallLog.Items.Add("Ensure Both Paths Have Valid Version.txt")}

    }else{[void]$var_lst_InstallLog.Items.Add("One Of The Paths Doesn't Exist")}
}

function Installation {
    $var_lst_InstallLog.Items.Clear()
    [System.Windows.Forms.Application]::DoEvents()
    $versionFlag = Compare-Versions

    if ($currentLocationFlag -eq $false){
        if(-not (Test-Path -Path $var_txt_LocalLocation.Text)){
            [void]$var_lst_InstallLog.Items.Add("Script Not Found In Local Directory")
            [void]$var_lst_InstallLog.Items.Add("Installing Script At C:\AutoPilot Validation")
            Copy-Item $var_txt_SharedDriveLocation.Text -Destination "C:\" -Recurse
    
            $var_lbl_InstallationStatus.Content = "True"
            $var_lbl_InstallationStatus.Foreground = [System.Windows.Media.Brushes]::Green
            $var_lbl_LatestVersionStatus.Content = "True"
            $var_lbl_LatestVersionStatus.Foreground = [System.Windows.Media.Brushes]::Green
    
        }elseif((Get-ChildItem -Path $var_txt_LocalLocation.Text -Force | Measure-Object).Count -eq 0){
            [void]$var_lst_InstallLog.Items.Add("Local Machine Has Empty Local Directory")
            [void]$var_lst_InstallLog.Items.Add("Providing Files For Directory")
            Remove-Item -Path $var_txt_LocalLocation.Text -Recurse -Force -Confirm:$false
            Copy-Item $var_txt_SharedDriveLocation.Text -Destination "C:\" -Recurse
    
            $var_lbl_InstallationStatus.Content = "True"
            $var_lbl_InstallationStatus.Foreground = [System.Windows.Media.Brushes]::Green
            $var_lbl_LatestVersionStatus.Content = "True"
            $var_lbl_LatestVersionStatus.Foreground = [System.Windows.Media.Brushes]::Green
    
        }elseif($versionFlag -eq $true){
            [void]$var_lst_InstallLog.Items.Add("Update Required!")
            [void]$var_lst_InstallLog.Items.Add("Updating Script With Latest Version")
            Remove-Item -Path $var_txt_LocalLocation.Text -Recurse -Force -Confirm:$false
            Copy-Item $var_txt_SharedDriveLocation.Text -Destination "C:\" -Recurse
    
            $var_lbl_InstallationStatus.Content = "True"
            $var_lbl_InstallationStatus.Foreground = [System.Windows.Media.Brushes]::Green
            $var_lbl_LatestVersionStatus.Content = "True"
            $var_lbl_LatestVersionStatus.Foreground = [System.Windows.Media.Brushes]::Green
        }
    }elseif($currentLocationFlag){
        [void]$var_lst_InstallLog.Items.Add("Can Only Execute Update From Shared Drive")
    }else{
        [void]$var_lst_InstallLog.Items.Add("Error: Debug if currentLocationFlag is set")
    }
}

$var_btn_Install.Add_Click({Installation})

# ====== Initial Status ====== #

$versionFlag = Compare-Versions

if ($AdminPrivilege){
    $var_lbl_ElevatedPriviledgeStatus.Content = "True"
    $var_lbl_ElevatedPriviledgeStatus.Foreground = [System.Windows.Media.Brushes]::Green
}
if (Test-Path -Path $DefaultLocalLocation){
    $var_lbl_InstallationStatus.Content = "True"
    $var_lbl_InstallationStatus.Foreground = [System.Windows.Media.Brushes]::Green
}
if($versionFlag -eq $false){
    $var_lbl_LatestVersionStatus.Content = "True"
    $var_lbl_LatestVersionStatus.Foreground = [System.Windows.Media.Brushes]::Green
}

if($currentLocationFlag){
    $var_lbl_LocalExecutionStatus.Content = "True"
    $var_lbl_LocalExecutionStatus.Foreground = [System.Windows.Media.Brushes]::Green
}


# ====== Execute Script Button Functionality ====== #

$var_btn_Execute.Add_Click({
    $versionFlag = Compare-Versions
    if(($versionFlag -eq $false) -and (Test-Path -Path "$($var_txt_LocalLocation.Text)\AutoPilot Validation Beta.ps1")){
        $jsonString = $config | ConvertTo-Json -Depth 5
        Set-Content -Path "$($var_txt_LocalLocation.Text)\Config.json" -Value $jsonString
        Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -File `"$($var_txt_LocalLocation.Text)\AutoPilot Validation Beta.ps1`""

        $psForm.Close()
    }else{
        $var_lst_InstallLog.Items.Clear()
        [void]$var_lst_InstallLog.Items.Add("Invalid Local Path or Version Mismatch")
        [void]$var_lst_InstallLog.Items.Add("$($var_txt_LocalLocation.Text)\AutoPilot Validation Beta.ps1 doesn't exist.")
    }
})

# ====== Config Checkboxes ====== #

if($config.CheckVersions){$var_chk_CheckVersions.IsChecked = "True"}
if($config.ValidateApplications){$var_chk_ValidateApplications.IsChecked = "True"}
if($config.TestInternet){$var_chk_TestInternet.IsChecked = "True"}
if($config.BitLockerProtection){$var_chk_BitLockerProtection.IsChecked = "True"}
if($config.XMLOutput){$var_chk_XMLOutput.IsChecked = "True"}
if($config.HTMLOutput){$var_chk_HTMLOutput.IsChecked = "True"}
if($config.AzureOutput){$var_chk_AzureOutput.IsChecked = "True"}

# ====== Config Checkboxes Functionality ====== #

$var_chk_CheckVersions.Add_Checked({$config.CheckVersions = $true})
$var_chk_CheckVersions.Add_UnChecked({$config.CheckVersions = $false})

$var_chk_ValidateApplications.Add_Checked({$config.ValidateApplications = $true})
$var_chk_ValidateApplications.Add_UnChecked({$config.ValidateApplications = $false})

$var_chk_TestInternet.Add_Checked({$config.TestInternet = $true})
$var_chk_TestInternet.Add_UnChecked({$config.TestInternet = $false})

$var_chk_BitLockerProtection.Add_Checked({$config.BitLockerProtection = $true})
$var_chk_BitLockerProtection.Add_UnChecked({$config.BitLockerProtection = $false})

$var_chk_XMLOutput.Add_Checked({$config.XMLOutput = $true})
$var_chk_XMLOutput.Add_UnChecked({$config.XMLOutput = $false})

$var_chk_HTMLOutput.Add_Checked({$config.HTMLOutput = $true})
$var_chk_HTMLOutput.Add_UnChecked({$config.HTMLOutput = $false})

$var_chk_AzureOutput.Add_Checked({$config.AzureOutput = $true})
$var_chk_AzureOutput.Add_UnChecked({$config.AzureOutput = $false})

# ====== Initialize Form ====== #

 $psForm.ShowDialog()