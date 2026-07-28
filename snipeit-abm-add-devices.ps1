<# Syncs Apple Business Manager (ABM) devices into Snipe-IT.

    .DESCRIPTION
        Azure Automation runbook that:
        1. Runs the child runbook 'snipeit-update-all-models' first (and stops if it
            does not complete) to ensure all models exist in Snipe-IT.
        2. Authenticates to ABM using a client-credentials JWT assertion (ES256 /
            P-256 EC key). Credentials (ClientId, KeyId, PrivateKey) are read from
            Azure Key Vault. The private key secret must be a Base64-encoded,
            unencrypted PKCS#8 P-256 PEM.
        3. Retrieves all org devices from ABM (paged).
        4. Compares ABM Macs and iPhones against existing Snipe-IT hardware (by
            serial number) to find devices missing from Snipe-IT.
        5. Creates the missing devices in Snipe-IT, mapping model, serial, purchase
            date, order number, warranty, and custom fields (IMEI, colour, part
            number, capacity, Intune flag).

        Authentication to Azure uses the Automation account's system-assigned managed
        identity. Requires modules: Az.Accounts, Az.KeyVault, Az.Automation.

    .NOTES
        ==================== INSTALLATION-SPECIFIC VALUES ====================
        Review/change these when deploying to a different environment:

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

        EDITABLE PROPERTIES region:
        $CategoryNames         - Snipe-IT category names (Desktop/Laptop/Phone)
        $statusNames           - Snipe-IT status label used for new assets (Available)
        $warranties            - Warranty length in months per device type
        $company               - Company name where the assets should be associated to in Snipe-IT ("Company name"

        CUSTOM FIELD NAMES:
        $CustomFieldNames      - Snipe-IT custom field DB column names; the trailing
                                IDs (_snipeit_imei_10, _7, _15, _16, _17) are unique
                                per Snipe-IT install and MUST be corrected. 
                                How to find your custom filed names: https://snipe-it.readme.io/reference/hardware-create
                                IMEI - text:  Will add the IMEI of the device, if it exist. 
                                Intune - checkbox: Make the checkbox true, since the device is in MDM
                                Colour - text: Add the colour of the device
                                PartNumber - text: Add the part number of the device like MGDE3QN/A 
                                deviceCapacity - text: Storage in the device, like 256GB
                                
                                If you don't want the custom fileds, remove or update in seciton 4.3

        HARD-CODED IN MAIN (Section 1 - child runbook call):
        AutomationAccountName  = "YOR NAME OF YOUR AUTOMATION ACCOUNT"
        ResourceGroupName      = "NAME OF AUTOMATION ACCOUNT RESOURCE GROUP"
        Runbook Name           = "NAME OF THE RUNBOOK THAT ADDS ALL MODELS (snipeit-update-all-models)"
        ======================================================================

#>
[CmdletBinding()]
param(
    [string] $KeyVaultName = 'itops-bb-azautomation',

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

$AZAUTAC   = "YOR NAME OF YOUR AUTOMATION ACCOUNT"
$AZAUTACRG = "NAME OF AUTOMATION ACCOUNT RESOURCE GROUP"
$AZAUTACRB = "snipeit-update-all-models"


# Friendly name -> SnipeIT lookups are resolved at runtime below.
$CategoryNames      = @{ Desktop = 'Desktop'; Laptop = 'Laptop'; Mobile = 'Phone';}
$CustomFieldNames   = @{ IMEI = '_snipeit_imei_10'; Intune = '_snipeit_intune_7'; Colour = '_snipeit_colour_15'; partNumber = '_snipeit_partnumber_16'; deviceCapacity = '_snipeit_devicecapacity_17' }
$statusNames        = @{ Available = 'Available'}
$warranties         = @{ Mac = '12'; iPhone = '12'}
$company            = "Company name"

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
            $resp.data | ForEach-Object {
                $device = $_

                # attributes.imei is an array on the ABM device object.
                # Surface it as a top-level 'imei' property so it shows in $allDevices.
                $imeiValue = $null
                if ($device.PSObject.Properties.Name -contains 'attributes' -and
                    $device.attributes.PSObject.Properties.Name -contains 'imei' -and
                    $device.attributes.imei) {
                    $imeiValue = ($device.attributes.imei | Where-Object { $_ }) -join ', '
                }

                $device | Add-Member -NotePropertyName 'imei' -NotePropertyValue $imeiValue -Force
                $devices.Add($device)
            }
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

function New-AppleDevice {
    param($dev)
    $mod = $allDevices.attributes | Where-Object { $_.serialNumber -eq $dev }
    $isMobile = $mod.productFamily -match 'iPhone'
    [PSCustomObject]@{
        status_id       = $Config.status_id
        model_id        = ($models | Where-Object {$_.model_number -eq $mod.productType}).id
        serial          = $mod.serialNumber
        purchase_date   = ([datetime]$mod.orderDateTime).ToString('yyyy-MM-dd')
        order_number    = $mod.orderNumber
        warranty        = if ($isMobile) { $warranties.iPhone }     else { $warranties.Mac } 
        colour          = $mod.color
        partNumber      = $mod.partNumber
        deviceCapacity  = $mod.deviceCapacity
        imei            = if ($isMobile) { (($allDevices | Where-Object {$_.id -eq $mod.serialNumber}).imei).split(',')[0] } else { $null } 
    }
}
#endregion

#region ============================ MAIN ============================

#region --- 1. Check Manufacturers and Models --- 

# Ensure that the runbook does not inherit an AzContext
Disable-AzContextAutosave -Scope Process

# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).context

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

$job = Start-AzAutomationRunbook `
    -AutomationAccountName $AZAUTAC `
    -ResourceGroupName $AZAUTACRG `
    -Name $AZAUTACRB `
    -DefaultProfile $AzureContext `
    -Wait

# $job here is the child's output stream, not a job object — get the real status:
$jobRecord = Get-AzAutomationJob `
    -AutomationAccountName $AZAUTAC `
    -ResourceGroupName $AZAUTACRG `
    -DefaultProfile $AzureContext |
    Sort-Object CreationTime -Descending |
    Where-Object { $_.RunbookName -eq $AZAUTACRB } |
    Select-Object -First 1

if ($jobRecord.Status -ne 'Completed') {
    throw "Child runbook ended with status '$($jobRecord.Status)' — stopping parent."
} else {}

Write-Output "Models added. Continue ..."
$null = $job 
#endregion

#region --- 2. Connect to ABM and get all devices ---

# 2.1 Connect to Azure with Managed Identity and retrieve ABM secrets from Key Vault
Write-Output "Connecting to Azure with Managed Identity..."
try {
    # -Identity uses the Automation account's system-assigned managed identity.
    $null = Connect-AzAccount -Identity
}
catch {
    throw "Managed Identity sign-in failed. Confirm the Automation account has a system-assigned identity and Az.Accounts is imported. Error: $($_.Exception.Message)"
}

# 2.2 Read ABM credentials from Key Vault
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

# 2.3 Retrieve all devices from ABM
Write-Output "Retrieving devices from Apple Business Manager..."
$allDevices = Get-AllOrgDevices -AccessToken $token -BaseUri $BaseUri
Write-Output "Retrieved $($allDevices.Count) device(s) from Apple Business Manager."

#endregion

#region --- 3. Find missing devices ---
# --- 3.1 Find missing Macs and iPhones in SnipeIT --- 
Write-Output "Anlaysing computers"
$limit  = 500

# 3.2 Categories
$categories         = (Invoke-SnipeITApi -Endpoint 'categories' -Method GET).rows
$categoryLaptopId   = ($categories | Where-Object name -eq $CategoryNames.Laptop).id
$categoryMobileId   = ($categories | Where-Object name -eq $CategoryNames.Mobile).id

# 3.3 Find all Laptops
Write-output "Finding all SnipeIT computers (macs)"

$offset = 0
$existingLaptops = [System.Collections.Generic.List[object]]::new()
do {
    $page = (Invoke-SnipeITApi -Endpoint "hardware?limit=$limit&offset=$($offset*$limit)&category_id=$($categoryLaptopId)&sort=id&order=asc" -Method GET).rows
    if ($page) { $existingLaptops.AddRange([object[]]$page) }
    $offset++
} while ($page.Count -eq $limit)

# 3.4 Compare to find missing devices
Write-Output "Comparing against ABM"
$abmComputers       = $allDevices.attributes | where-object {$_.productFamily -eq "Mac"} 
$missingComputers   = Compare-Missing -Existing $existingLaptops.serial -Source $abmComputers.serialNumber

# 3.5 Find all Mobiles
Write-output "Finding all SnipeIT iPhones"
$offset = 0
$existingMobiles = [System.Collections.Generic.List[object]]::new()
do {
    $page = (Invoke-SnipeITApi -Endpoint "hardware?limit=$limit&offset=$($offset*$limit)&category_id=$($categoryMobileId)&sort=id&order=asc" -Method GET).rows
    if ($page) { $existingMobiles.AddRange([object[]]$page) }
    $offset++
} while ($page.Count -eq $limit)

# 3.6 Compare to find missing devices
Write-Output "Comparing against ABM"
$abmPhones          = $allDevices.attributes | where-object {$_.productFamily -eq "iPhone"} 
$missingMobiles     = Compare-Missing -Existing $existingMobiles.serial -Source $abmPhones.serialNumber

#endregion

#region --- 4. Add Macs and iPhones to SnipeIT ---
if($missingComputers -or $missingMobiles){
    Write-Output "Gathering SnipeIT properties"
    
    # 4.1 Models, Manufacturer, EOL, and Deprecation
    $Config = @{
        companyId      = ((Invoke-SnipeITApi -Endpoint 'companies?sort=id&order=asc' -Method GET).rows | Where-Object {$_.name -eq $company }).id
        status_id      = ((Invoke-SnipeITApi -Endpoint 'statuslabels' -Method GET).rows | Where-Object {$_.name -eq $statusNames.Available}).id
        PurchaseDate   = (Get-Date -Day 1).AddMonths(1).ToString('yyyy-MM-dd')
    }
    $models            = ((Invoke-SnipeITApi -Endpoint 'models' -Method GET).rows)
    
    $missingDevices = [System.Collections.Generic.List[object]]::new()

    # 4.2 Add missing computers and mobiles to array
    if (@($missingComputers).Count -gt 0) {
        $missingComputers | ForEach-Object { $missingDevices.Add((New-AppleDevice $_)) }
    }
    if (@($missingMobiles).Count -gt 0) {
        $missingMobiles | ForEach-Object { $missingDevices.Add((New-AppleDevice $_)) }
    }

    # 4.3 Add missing devices to SnipeIT
    foreach ($d in $missingDevices) {
     
        $ExtraFields = @{  
                            $CustomFieldNames.Colour = $d.colour;
                            $CustomFieldNames.Intune = "Yes" ;
                            $CustomFieldNames.partNumber = $d.partNumber;
                            $CustomFieldNames.deviceCapacity = $d.deviceCapacity;
                        }
        if ($null -ne $d.imei -and $d.imei -ne "") {
            $ExtraFields[$CustomFieldNames.imei] = $d.imei
        }

        $Body = @{
            status_id       = $d.status_id
            model_id        = $d.model_id
            serial          = $d.serial
            purchase_date   = $d.purchase_date
            order_number    = $d.order_number
            warranty_months = $d.warranty
        }
        $ExtraFields.GetEnumerator() | ForEach-Object { $Body[$_.Name] = $_.Value }

        $result = Invoke-SnipeITApi -Endpoint 'hardware' -Method POST -Body ($Body | ConvertTo-Json)

        if ($result.status -ne 'success') {
            Write-Output "Error creating device: $$d.serial. Error message: $($result.messages)"
            return $result
        } else { 
            Write-Output "Device with serial $($d.serial) created"
        }
    }

} else {
    Write-output "No missing ABM devices"
}
#endregion
