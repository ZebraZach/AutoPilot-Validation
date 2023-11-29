# ====== Initialization ====== #

$currentLocation = if($PSScriptRoot){$PSScriptRoot}else{Get-Location}
try{$currentLocation = [System.IO.Path]::GetFullPath($currentLocation)}
catch{}

# ====== WPF XML Directory ====== #

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$xamlFile = "$currentLocation\XML Directory.xaml"

$inputXAML=Get-Content -Path $xamlFile -Raw
$inputXAML=$inputXAML -replace 'mc:Ignorable="d"','' -replace "x:N","N" -replace '^<Win.*','<Window'
[XML]$XAML=$inputXAML

$reader = New-Object System.Xml.XmlNodeReader $XAML

try {
    $psForm3 = [Windows.Markup.XamlReader]::Load($reader)
}catch{
    Write-Error $_.Exception
    throw
}

$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try{
        Set-Variable -Name "var_$($_.Name)" -Value $psForm3.FindName($_.Name) -ErrorAction Stop
    }catch{
        Write-Error $_.Exception
        throw
    }
}

# ====== WPF XML Directory ====== #

$xamlFile2 = "$currentLocation\Main - XML Reader.xaml"

$inputXAML2=Get-Content -Path $xamlFile2 -Raw
$inputXAML2=$inputXAML2 -replace 'mc:Ignorable="d"','' -replace "x:N","N" -replace '^<Win.*','<Window'
[XML]$XAML2=$inputXAML2

$reader2 = New-Object System.Xml.XmlNodeReader $XAML2

try {
    $psForm4 = [Windows.Markup.XamlReader]::Load($reader2)
}catch{
    Write-Error $_.Exception
    throw
}

$xaml2.SelectNodes("//*[@Name]") | ForEach-Object {
    try{
        Set-Variable -Name "var_$($_.Name)" -Value $psForm4.FindName($_.Name) -ErrorAction Stop
    }catch{
        Write-Error $_.Exception
        throw
    }
}

# ====== XML Directory ====== #
## ====== Grab XML Content ====== ##

Get-Variable var_*

$var_txt_XMLDirectory.Text = "Choose Valid XML Directory"

function XML_Directory {

    $OutputFolderXML = New-Object System.Windows.Forms.FolderBrowserDialog
    $OutputFolderXML.ShowDialog()
    $XMLDirectory = $OutputFolderXML.SelectedPath

    if ( Valid_XML_Directory -Directory $XMLDirectory ) {
        $XMLDirectory = $OutputFolderXML.SelectedPath
        $var_txt_XMLDirectory.Text = $XMLDirectory
        $psForm3.Close()
        Initialize_XMLReader
        $psForm4.ShowDialog()
    } else {
        $var_txt_XMLDirectory.Text = $XMLDirectory
        $var_lbl_XMLDirectory.Foreground = [System.Windows.Media.Brushes]::Red
        $var_lbl_XMLDirectory.Content = "Invalid XML Directory"
    }
}

function Valid_XML_Directory {
    param ( [String]$Directory )

    if ( -not ( Test-Path -Path $Directory ) -or -not ( Get-ChildItem -Path $Directory )) {
        return $false
    } else {
        $childItems = Get-ChildItem -Path $Directory
        foreach( $childItem in $childItems ) {
            if ( $childItem.Extension -ne '.xml' ) {
                return $false
            }
        }
        return $true
    }
}

$var_btn_XMLDirectory.Add_Click({ XML_Directory })

# ====== XML Reader ====== #
## ====== Initialization ====== ##

function Initialize_XMLReader {
    Initialize_DDL
}

$var_ddl_Dates.Add_SelectionChanged({ DDL_Date_Selection })

### ====== Drop Down List - Dates ====== ###

function Initialize_DDL {

    $var_txt_XMLCurrentDirectory.Text = $var_txt_XMLDirectory.Text

    $listDates = [System.Collections.Generic.HashSet[string]]::new()
    $dateChildItems = Get-ChildItem -Path $var_txt_XMLCurrentDirectory.Text -Filter "*.xml"

    foreach ( $childItem in $dateChildItems ) {
        if ( $childItem.Name -match "(\d{14})" ) {
            $dateString = $matches[1]

            try {
                $date = [DateTime]::ParseExact( $dateString, 'yyyyMMddHHmmss' , $null )

                $null = $listDates.Add( $date.ToString( 'yyyyMMddHHmmss' ))
            } catch {
                Write-Error "Invalid Date Formated In File Name: $($childItem.Name)"
            }
        }
    }

    foreach( $date in $listDates ) {
        $formattedDate = $date.Insert(4, "-").Insert(7, "-").Insert(10, "-").Insert(13, "-").Insert(16, "-")
        $var_ddl_Dates.Items.Add($formattedDate)
    }
}

### ====== Drop Down List Selection Functionality ====== ###

$XMLCustomObjects = @{}

function DDL_Date_Selection {
    $script:XMLCustomObjects = @{}
    
    $XMLConversionPath = $var_txt_XMLCurrentDirectory.Text
    $machineName = Split-Path -Path $XMLConversionPath -Leaf

    $dateSelected = $var_ddl_Dates.SelectedItem
    $dateSelectedConverted = $dateSelected.Replace("-", "")
    $fileTypes = @( "Ethernet", "Running", "Validated", "Version", "VolumeC", "WiFi" )

    foreach ( $fileType in $fileTypes) {
        $fileName = "$XMLConversionPath\$dateSelectedConverted--$machineName--$fileType.xml"
        if ( Test-Path -Path $fileName ) {
            $script:XMLCustomObjects[$fileType] = Import-Clixml -Path $fileName
        }
    }
    Write-Host $script:XMLCustomObjects.Ethernet
}

## ====== Data Tables ====== ##
### ====== Version Check Data Table ====== ###

$versionCheckDataTable = New-Object System.Data.DataTable


$psForm3.ShowDialog()