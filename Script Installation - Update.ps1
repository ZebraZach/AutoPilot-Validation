# ====== Initialization ====== #

$SharedDriveDirectory = "\\wdmj07sxfg\AutoPilot Testing\Beta - AutoPilot Validation"
$NewScriptLocation = "C:\Beta - AutoPilot Validation"

$HostAnswer = Read-Host "Press 1, 2, or 3"

function Copy-And-Update {
    param( [string]$CheckPath )

    if ( -not ( Test-Path -Path $CheckPath )) { Copy-Item -Path $SharedDriveDirectory -Destination $NewScriptLocation -Recurse }
    
    else {

        if ( Compare-Versions ) {
        Remove-Item -Path $NewScriptLocation -Recurse -Force
        Start-Sleep -seconds 3
        Copy-Item -Path $SharedDriveDirectory -Destination $NewScriptLocation -Recurse
        }

        else { Write-Host "Latest version is already installed!" }}
}

function Compare-Versions {

    $SharedDriveVersion = [Version]( Get-Content -Path "$SharedDriveDirectory\Version.txt" )
    $HostMachineVersion = [Version]( Get-Content -Path "$NewScriptLocation\Version.txt" )

    return $SharedDriveVersion -gt $HostMachineVersion
}

Switch ( $HostAnswer ){
    1 { Copy-And-Update -CheckPath $NewScriptLocation 
        Start-Sleep -seconds 7 
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"C:\Beta - AutoPilot Validation\AutoPilot Validation Beta.ps1`"" -Verb RunAs 
    }

    2 { Copy-And-Update -CheckPath $NewScriptLocation }
    
    Default { Exit }
}