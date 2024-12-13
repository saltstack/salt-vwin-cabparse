################################################################################
#
# This script generates the WSUS JSON Data for VWIN based on wsusscn2.cab. This
# file is provided by Microsoft and is updated every time updates are released
# (patch Tuesday). It contains only Security Updates, Service Packs, and Update
# Rollups.
#
# This script does the following:
# - Downloads the wsuscn2.cab file from Microsoft
# - Expands the cab file (this extracts many cab files)
# - Expands all those cab files into the same directory
# - Gathers information from all .xml files for English
# - Generates a JSON file containing all that information
#
# Outputs JSON in the following format:
#
#   {
#       "UpdateID (GUID)": {
#           "Title": "The title",
#           "Description": "A longer description",
#           "KBs": ["KB1235"],
#           "CVEs": []
#           "UpdateID": "A GUID",
#           "AdditionalInfoUrl": ["A url"],
#       },
#       ...
#   }
# 
################################################################################
[CmdletBinding()]
param()

################################################################################
# Script Settings
################################################################################
# We want to stop on errors
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

################################################################################
# Script Variables
################################################################################
$start_time = $(Get-Date)
$uri = "https://go.microsoft.com/fwlink/?LinkID=74689"
$cab_file = "$env:TEMP\wsusscn2.cab"
$cab_dir = "$env:TEMP\wsusscn2"
$cur_dir = Get-Location
$json_file = "$cur_dir\wsus_updates.json"

################################################################################
# Script Functions
################################################################################
function Expand-Cab {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("s")]
        # The cab file to extract
        [String]$Source,

        [Parameter(Mandatory=$true)]
        [Alias("t")]
        # The directory to extract to
        [String] $Target
    )
    Write-Verbose "Source: $Source"
    Write-Verbose "Target: $Target"
    # Create target directory if it doesn't exist
    if ( ! ( Test-Path -Path $Target ) ) {
        Write-Verbose "Creating $Target"
        New-Item -Path $Target -ItemType Directory -Force | Out-Null
        if ( ! ( Test-Path -Path $Target ) ) {
            Write-Host "Failed to create directory: $Target"
            exit 1
        }
    }
    # Expand cab file
    Write-Verbose "Expanding $Source"
    $cmd = "cmd.exe"
    $args = "/c expand.exe `"$Source`" -f:* `"$Target`" > nul 2>&1"
    Write-Verbose "$cmd $args"
    Start-Process -FilePath $cmd `
                  -ArgumentList $args `
                  -Wait `
                  -WindowStyle Hidden | Out-Null
}

################################################################################
# Script Begin
################################################################################
Write-Host "Generate VWin Data from wsusscn2.cab"

# Downloading
Write-Verbose "URI: $uri"
Write-Verbose "File: $cab_file"
$elapsed_time = $(Get-Date) - $start_time
$total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
Write-Host "- Downloading wsusscn2.cab ($total_time): " -NoNewline
Invoke-WebRequest -Uri $uri -OutFile $cab_file -UseBasicParsing
if ( Test-Path -Path $cab_file ) {
    Write-Host "SUCCESS" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    exit 1
}

# Extracting main cab
$elapsed_time = $(Get-Date) - $start_time
$total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
Write-Host "- Expanding wsusscn2.cab ($total_time): " -NoNewline
if ( Test-Path -Path "$env:SystemRoot\System32\expand.exe" ) {
    Expand-Cab -Source $cab_file -Target $cab_dir
}
if ( Test-Path -Path "$cab_dir\package.cab" ) {
    Write-Host "SUCCESS" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    exit 1
}

# Extract all cabs in the cab file to their own directories
Write-Host "Extracting all internal cab files"
Get-ChildItem $cab_dir -File -Filter "*.cab" | ForEach-Object {
    $file_name = $_.Name
    $dir_name = "expanded"
    $elapsed_time = $(Get-Date) - $start_time
    $total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
    Write-Host "- Expanding $file_name` ($total_time): " -NoNewline
    Expand-Cab -Source $cab_dir\$file_name -Target $cab_dir\$dir_name
    if ( Test-Path -Path "$cab_dir\$file_name" ) {
        Write-Host "SUCCESS" -ForegroundColor Green
    } else {
        Write-Host "FAILED" -ForegroundColor Red
        exit 1
    }
}

# Create new empty hash table for all updates with KBs
$dict_updates = @{}

# Get a list of all the files in the expanded\l\en directory because we only
# want updates in English
$update_files = Get-ChildItem -Path "$cab_dir\expanded\l\en" -File | Sort-Object {[int]($_.Name)}
$total_files = $update_files.Length
$total_processed = 0

Write-Host "Gathering data from $total_files updates"

# Get info from X, C, and L
try {
    $update_files | ForEach-Object {
        # They will all have this file name
        $file_name = $_.Name    
        $percentage = [math]::round( ( $total_processed / $total_files ) * 100 )
        $elapsed_time = $(Get-Date) - $start_time
        $total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
        $msg = "`r - Processing $file_name ($total_processed of $total_files) : $percentage% Complete : ($total_time): "
        Write-Host $msg -NoNewline

        # New empty hash table for single update
        $dict_update = @{}
    
        # Get X Information (KBArticleID)
        # This can have multiple root elements, so we need to put them all in a
        # single root element
        $xml_content = Get-Content -Path "$cab_dir\expanded\x\$file_name"
        [XML]$xml = "<root>" + $xml_content + "</root>"
        $dict_update["KBs"] = @("KB" + $xml.root.ExtendedProperties.KBArticleID)
        $dict_update["CVEs"] = @()

        # If there is no associated KB, we skip
        if ( ! $xml.root.ExtendedProperties.KBArticleID ) {
            # Increment the counter
            $total_processed += 1
            return # behaves like continue
        }

        # Get C Information (UpdateID)
        # This can have multiple root elements, so we need to put them all in a
        # single root element
        $xml_content = Get-Content -Path "$cab_dir\expanded\c\$file_name"
        [XML]$xml = "<root>" + $xml_content + "</root>"
        $dict_update["UpdateID"] = $xml.root.UpdateIdentity.UpdateID

        # Get C Information (Title, Description, MoreInfoUrl)
        [XML]$xml = Get-Content -Path "$cab_dir\expanded\l\en\$file_name"
        $dict_update["Title"] = $xml.LocalizedProperties.Title
        $dict_update["Description"] = $xml.LocalizedProperties.Description
        $dict_update["AdditionalInfoUrl"] = @($xml.LocalizedProperties.MoreInfoUrl)

        # Save this update to the updates dict. UpdateID is the primary key
        $dict_updates[$dict_update["UpdateID"]] = $dict_update

        # Increment the counter
        $total_processed += 1
    }
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "An error occured:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
Write-Host "SUCCESS" -ForegroundColor Green

$elapsed_time = $(Get-Date) - $start_time
$total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
Write-Host "Generating JSON file ($total_time): " -NoNewline
# Write to a file, UTF8, no BOM
$UTF8NoBOM = New-Object System.Text.UTF8Encoding $false
$json_data = $dict_updates | ConvertTo-Json | Out-String
[System.IO.File]::WriteAllText($json_file, $json_data, $UTF8NoBOM)
if ( Test-Path -Path $json_file ) {
    Write-Host "SUCCESS" -ForegroundColor Green
} else {
    Write-Host "FAILED" -ForegroundColor Red
    exit 1
}

$elapsed_time = $(Get-Date) - $start_time
$total_time = "{0:HH:mm:ss}" -f ([datetime]$elapsed_time.Ticks)
Write-Host "Generate VWin Data Complete ($total_time)"