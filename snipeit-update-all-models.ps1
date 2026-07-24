<# This script is checking if manufacturers and models from Intune, Autopilot and Apple Business Manager exist in Snipe IT 
    Runs as an Azure Automation runbook. Using the Automation account's system-assigned Managed Identity it:
      1. Authenticates to ABM and pulls all org devices.
      2. Connects to Microsoft Graph and pulls all Intune managed devices and Autopilot device identities.
      3. Compares the manufacturers found against those in Snipe-IT and creates any that are missing.
      4. Compares Windows and Apple (Mac/iPhone) models against Snipe-IT and creates any that are missing, 
         setting category, fieldset, EOL and depreciation. 

    .PREREQUISITES
        - Azure Automation account with a system-assigned Managed Identity that has:
            * Get access on the Key Vault secrets below.
            * Directory permissions for Graph (DeviceManagementManagedDevices.Read.All, DeviceManagementServiceConfig.Read.All)
        - Modules imported into the Automation account: Az.Accounts, Az.KeyVault, Microsoft.Graph.Authentication
        - The target categories and fieldsets (see below) must already exist in Snipe-IT; the script looks them up by name and will get $null ids if they don't match.

        ============================ INSTALLATION-SPECIFIC VALUES ============================
        Change these to match your own tenant / Snipe-IT / ABM setup.

        PARAMETERS (top of script)
        $KeyVaultName          Name of your Key Vault holding the ABM credentials.
        $ClientIdSecretName    Key Vault secret names for the ABM API credentials. (the "BUSINESSAPI.xxxx-..." client id)
        $KeyIdSecretName       The key id
        $PrivateKeySecretName  The PrivateKey secret must be a base64-encoded, unencrypted PKCS#8 P-256 PEM
                               Powershell command for PEM 
                               $pem = Get-Content ./abm_key_pkcs8.pem -Raw [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pem)) | Set-Clipboard)
        $Scope / $BaseUri /    Apple ABM OAuth endpoints. Usually left as-is; only
        $TokenUri / $Audience   change if Apple changes their API.

        AUTOMATION VARIABLES (set in the Automation account, NOT in the script)
        'SnipeITURL'           Base URL of your Snipe-IT API, e.g.
                                https://snipe.example.com/api/v1/  (note trailing slash).
        'SnipeITAPI'           Snipe-IT personal API token (Bearer).

        EDITABLE PROPERTIES (the $CategoryNames / $FieldsetNames / $depreciation / $EOLs block)
        $CategoryNames         Must match your Snipe-IT category NAMES exactly
                                (Laptop / Phone here).
        $FieldsetNames         Must match your Snipe-IT fieldset NAMES exactly
                                (Computers / Devices with IMEI here).
        $depreciation          Snipe-IT depreciation record IDs (numbers), per device
                                type. Look these up in your own Snipe-IT instance.
        $EOLs                  End-of-life in MONTHS per device type.
        ====================================================================================
#>
[CmdletBinding()]
param(
    [string] $KeyVaultName = 'YOUR-AZURE-KEYVAULT-NAME',

    [string] $ClientIdSecretName   = 'ABM-ClientId',
    [string] $KeyIdSecretName      = 'ABM-KeyId',
    [string] $PrivateKeySecretName = 'ABM-PrivateKey',

    [string] $Scope    = 'business.api',
    [string] $BaseUri  = 'https://api-business.apple.com',
    [string] $TokenUri = 'https://account.apple.com/auth/oauth2/token',
    [string] $Audience = 'https://account.apple.com/auth/oauth2/v2/token'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region ============================ EDITABLE PROPERTIES ============================

$SnipeURL = Get-AutomationVariable -Name 'SnipeITURL'
$SnipeAPI = Get-AutomationVariable -Name 'SnipeITAPI'

# Friendly name -> SnipeIT lookups are resolved at runtime below.

$CategoryNames = @{ Laptop = 'Laptop'; Mobile = 'Phone'}
$FieldsetNames = @{ Computers = 'Computers'; Mobile = 'Devices with IMEI' }
$depreciation  = @{ PC = '3'; Mac = '2'; iPhone = '5'; Std = '1'}
$EOLs          = @{ PC = '36'; Mac = '36'; Phones = '24'}

#endregion

#region ============================ FUNCTIONS ============================

function ConvertTo-Base64Url {
    param([Parameter(Mandatory)][byte[]] $Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-ClientAssertion {
    param(
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $KeyId,
        [Parameter(Mandatory)][string] $PrivateKeyPem,
        [Parameter(Mandatory)][string] $Audience
    )

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportFromPem($PrivateKeyPem)
    }
    catch {
        throw "Failed to import EC private key. Ensure the Key Vault secret holds an unencrypted PKCS#8 P-256 PEM (including BEGIN/END lines). Underlying error: $($_.Exception.Message)"
    }

    $header = [ordered]@{
        alg = 'ES256'
        kid = $KeyId
        typ = 'JWT'
    } | ConvertTo-Json -Compress

    $now = [DateTimeOffset]::UtcNow
    $payload = [ordered]@{
        sub = $ClientId
        aud = $Audience
        iss = $ClientId
        iat = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(15).ToUnixTimeSeconds()
        jti = [guid]::NewGuid().ToString()
    } | ConvertTo-Json -Compress

    $encHeader  = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))
    $encPayload = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
    $signingInput = "$encHeader.$encPayload"

    $sigBytes = $ecdsa.SignData(
        [Text.Encoding]::ASCII.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation
    )
    $encSig = ConvertTo-Base64Url $sigBytes

    "$signingInput.$encSig"
}

function Get-AccessToken {
    param(
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $Assertion,
        [Parameter(Mandatory)][string] $Scope,
        [Parameter(Mandatory)][string] $TokenUri
    )

    $body = @{
        grant_type            = 'client_credentials'
        client_id             = $ClientId
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $Assertion
        scope                 = $Scope
    }

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $TokenUri `
            -ContentType 'application/x-www-form-urlencoded' -Body $body
    }
    catch {
        $detail = ''
        if ($_.ErrorDetails.Message) { $detail = " Response: $($_.ErrorDetails.Message)" }
        throw "Token request failed.$detail"
    }

    if (-not $resp.access_token) { throw "No access_token in token response." }
    $resp.access_token
}

function Get-AllOrgDevices {
    param(
        [Parameter(Mandatory)][string] $AccessToken,
        [Parameter(Mandatory)][string] $BaseUri
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $devices = [System.Collections.Generic.List[object]]::new()
    $uri = "$BaseUri/v1/orgDevices?limit=100"
    $page = 0

    while ($uri) {
        $page++
        Write-Verbose "Fetching page $page : $uri"
        $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

        if ($resp.PSObject.Properties.Name -contains 'data' -and $resp.data) {
            $resp.data | ForEach-Object { $devices.Add($_) }
        }

        $uri = $null
        if ($resp.PSObject.Properties.Name -contains 'links' -and
            $resp.links.PSObject.Properties.Name -contains 'next' -and
            $resp.links.next) {
            $uri = $resp.links.next
        }
    }

    $devices
}

function Get-KeyVaultSecretText {
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory)][string] $SecretName
    )
    $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName
    if (-not $secret) { throw "Secret '$SecretName' not found in vault '$VaultName'." }
    # Az.KeyVault 4.x+ returns a SecureString in .SecretValue
    [System.Net.NetworkCredential]::new('', $secret.SecretValue).Password
}

function Invoke-SnipeITApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method,
        $Body
    )

    $uri    = $SnipeURL + $Endpoint
    $header = @{
        Authorization = "Bearer $SnipeAPI"
        accept        = 'Application/json'
    }

    if ($Method -eq 'GET') {
        Invoke-RestMethod -Method GET -Uri $uri -Headers $header
    }
    else {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $header -Body $Body -ContentType 'application/json'
    }
}

function Compare-Missing {
    # Returns items present in $Source (Intune) but absent from $Existing (SnipeIT).
    [CmdletBinding()]
    param(
        $Existing,
        $Source
    )

    if (-not $Existing) { return $Source }

    $left  = [string[]]$Existing
    $right = [string[]]$Source
    [string[]][Linq.Enumerable]::Except($right, $left, [System.StringComparer]::OrdinalIgnoreCase)
}

function New-WindowsModelObject {
    param($dev)
    $mod = $allwindowsdevices | Where-Object { $_.model -eq $dev } | Select-Object -First 1
    [PSCustomObject]@{
        Name            = $mod.model
        manufacturer_id = ($snipeManufacturers | Where-Object { $_.name -eq $mod.manufacturer }).id
        model_number    = $mod.model
        category_id     = $categoryLaptopId
        eol             = $EOLs.PC
        fieldset_id     = $fieldsetComputersId
        depreciation_id = $depreciation.PC
    }
}

function New-AppleModelObject {
    param($dev)
    $mod = $allMacDevices.attributes | Where-Object { $_.productType -eq $dev } | Select-Object -First 1
    $isMobile = $mod.productFamily -match 'iPhone'
    [PSCustomObject]@{
        Name            = $mod.deviceModel
        manufacturer_id = ($snipeManufacturers | Where-Object { $_.name -eq 'Apple' }).id
        model_number    = $mod.productType
        category_id     = if ($isMobile) { $categoryPhoneId }     else { $categoryLaptopId }
        eol             = if ($isMobile) { $EOLs.Phones }         else { $EOLs.Mac }
        fieldset_id     = if ($isMobile) { $fieldsetMobileId }    else { $fieldsetComputersId }
        depreciation_id = if ($isMobile) { $depreciation.iPhone } else { $depreciation.Mac }
    }
}

#endregion

#region ============================ MAIN ============================

#region --- 1. Connect to ABM and get all devices ---

# 1.1 Connect to Azure with Managed Identity and retrieve ABM secrets from Key Vault
Write-Output "Connecting to Azure with Managed Identity..."
try {
    # -Identity uses the Automation account's system-assigned managed identity.
    $null = Connect-AzAccount -Identity
}
catch {
    throw "Managed Identity sign-in failed. Confirm the Automation account has a system-assigned identity and Az.Accounts is imported. Error: $($_.Exception.Message)"
}

# 1.2 Read ABM credentials from Key Vault
Write-Output "Reading ABM credentials from Key Vault '$KeyVaultName'..."
$clientId      = Get-KeyVaultSecretText -VaultName $KeyVaultName -SecretName $ClientIdSecretName
$keyId         = Get-KeyVaultSecretText -VaultName $KeyVaultName -SecretName $KeyIdSecretName
$pemRaw = Get-KeyVaultSecretText -VaultName $KeyVaultName -SecretName $PrivateKeySecretName
$privateKeyPem = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pemRaw))

Write-Output "Building client assertion..."
$assertion = New-ClientAssertion -ClientId $clientId -KeyId $keyId `
    -PrivateKeyPem $privateKeyPem -Audience $Audience

Write-Output "Exchanging assertion for access token..."
$token = Get-AccessToken -ClientId $clientId -Assertion $assertion `
    -Scope $Scope -TokenUri $TokenUri

# 1.3 Retrieve all devices from ABM
Write-Output "Retrieving models from Apple Business Manager..."
$allMacDevices = Get-AllOrgDevices -AccessToken $token -BaseUri $BaseUri

#endregion#>

#region --- 2. Gather Intune & Autopilot devices ---
Write-Output "Connecting to MS Graph with Managed Identity..."
try {
    Connect-MgGraph -Identity -NoWelcome
}
catch {
    throw "Managed Identity sign-in failed. Error: $($_.Exception.Message)"
}

Write-Output "Collecting all Intune and Autopilot models"
$graphBase        = 'https://graph.microsoft.com/v1.0/deviceManagement'
$intuneDevices    = (Invoke-MgGraphRequest -Method GET "$graphBase/managedDevices").value | Where-Object serialNumber -ne ''
$autopilotDevices = (Invoke-MgGraphRequest -Method GET "$graphBase/windowsAutopilotDeviceIdentities").value
$allwindowsdevices = $intuneDevices + $autopilotDevices

#endregion

#region --- 3. Manufacturers ---

# 3.1 Manufacturers
Write-Output 'Analysing manufacturers'
$intuneManufacturers  = @(
    ($intuneDevices    | Select-Object -ExpandProperty manufacturer -Unique) +
    ($autopilotDevices | Select-Object -ExpandProperty manufacturer -Unique) + "Apple"
) | Sort-Object -Unique
$snipeManufacturers   = (Invoke-SnipeITApi -Endpoint 'manufacturers' -Method GET).rows
$missingManufacturers = Compare-Missing -Existing ($snipeManufacturers.name | Sort-Object) -Source $intuneManufacturers

if ($missingManufacturers) {
    Write-Output "Adding new manufacturer(s)"
    foreach ($manufacturer in $missingManufacturers) {
        $body = @{ name = $manufacturer } | ConvertTo-Json
        Invoke-SnipeITApi -Endpoint 'manufacturers' -Method POST -Body $body
        Write-Output "Manufacturer created: $manufacturer"
    }
    $snipeManufacturers = (Invoke-SnipeITApi -Endpoint 'manufacturers' -Method GET).rows
}
else {
    Write-Output 'No new manufacturers'
}

#endregion 

#region --- 4 Models ---
Write-Output "Gathering SnipeIT models"
$snipeModels   = (Invoke-SnipeITApi -Endpoint 'models' -Method GET).rows | 
                    Select-Object Id, model_number, manufacturer, name, category, eol, depreciation -Unique | Sort-Object model_number

# 4.1 Analysing all models
# 4.1.1 Windows & autopilot
Write-Output 'Analysing Intune and Autopilot models'

$allwindowsmodels = (($intuneDevices | where-object {$_.operatingSystem -eq "Windows"} | select-object model) + ($autopilotdevices | select-object model)) | Select-Object model -Unique | Sort-Object model
$missingWindowsModels = Compare-Missing -Existing ($snipeModels.model_number) -Source $allwindowsmodels.model

# 4.1.2 Android

# 4.1.3 Mac and iPhone

Write-Output "Analysing ABM Models"
$allMacModels = $allMacDevices.attributes | Select-Object producttype -Unique| Sort-Object producttype -unique | 
    Sort-Object producttype | Group-Object producttype | ForEach-Object {$_.Group[0]}
$missingAppleModels = Compare-Missing -Existing ($snipeModels.model_number) -source $allMacModels.productType

# 4.2 Adding all missing models
if($missingWindowsModels -or $missingAppleModels){
    Write-Output "Adding new models"
    $categories    = (Invoke-SnipeITApi -Endpoint 'categories' -Method GET).rows
    $categoryLaptopId   = ($categories | Where-Object {$_.name -eq $CategoryNames.Laptop}).id
    $categoryPhoneId    = ($categories | Where-Object {$_.name -eq $CategoryNames.mobile}).id
    
    $fieldsets        = (Invoke-SnipeITApi -Endpoint 'fieldsets' -Method GET).rows
    $fieldsetComputersId   = ($fieldsets | Where-Object {$_.name -eq $FieldsetNames.Computers}).id
    $fieldsetMobileId      = ($fieldsets | Where-Object {$_.name -eq $FieldsetNames.Mobile}).id

    $missingModels = [System.Collections.Generic.List[object]]::new()
   
    if (@($missingWindowsModels).Count -gt 0) {
        $missingWindowsModels | ForEach-Object { $missingModels.Add((New-WindowsModelObject $_)) }
    }

    if (@($missingAppleModels).Count -gt 0) {
        $missingAppleModels | ForEach-Object { $missingModels.Add((New-AppleModelObject $_)) }
    }
    
    foreach($m in $missingModels){
        $body = @{
            name            = $m.Name
            manufacturer_id = $m.manufacturer_id
            model_number    = $m.model_number
            category_id     = $m.category_id
            eol             = $m.eol
            fieldset_id     = $m.fieldset_id
        } | ConvertTo-Json
        $created = Invoke-SnipeITApi -Endpoint 'models' -Method POST -Body $body

        # Depreciation can't be set on create, so PATCH it separately.
        $depBody = @{ depreciation_id = $m.depreciation_id } | ConvertTo-Json
        Invoke-SnipeITApi -Endpoint "models/$($created.payload.id)" -Method PATCH -Body $depBody
        Write-Output "Model created: $($m.name)"
    }

} else { Write-Output "No new models" }

#endregion

#endregion
