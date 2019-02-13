Set-strictmode -version latest
$ErrorActionPreference = 'stop'

Import-Module ServiceFabric
function winvault {
    <#
    .SYNOPSIS
    Tool to manage JSON secrets files

    .DESCRIPTION
    winvault is a complete solution to manage the lifecycle of your secrets as key/value pairs into encrypted JSON files.
    It uses X509 certificates stored in your computer to do the encryption.
    As the files are encrypted they can be stored and versioned into git.

    .PARAMETER create
    Switch to create a new secrets JSON file based on the thumbprint of an existing X509 certificate stored in the local Store

    .PARAMETER edit
    Switch to edit an existing secrets JSON file using your preferred editor (Notepad++ by default)

    .PARAMETER editCSV
    Switch to edit an existing secrets JSON file using your preferred CSV editor (Ron's editor by default)

    .PARAMETER view
    Switch to view the uncrypted content of an existing secrets JSON file as JSON in the standard output

    .PARAMETER viewCSV
    Switch to view the uncrypted content of an existing secrets JSON file as table in the standard output

    .PARAMETER encrypt
    Switch to encrypt in-place the content of an existing secrets JSON file

    .PARAMETER decrypt
    Switch to decrypt in-place the content of an existing secrets JSON file

    .PARAMETER validate
    Switch to validate the content of an existing secrets JSON file against a JSON schema

    .PARAMETER update
    Switch to create/update a key/value pair in an existing secrets JSON file

    .PARAMETER updateCSV
    Switch to update in-place the content of an existing secrets JSON file based on a CSV file with the right format (<Secret Name>, <Secret Value>)

    .PARAMETER schemaJSON
    Switch to generate a JSON schema, either a default one or one based on an existing secrets JSON file

    .PARAMETER secretJsonFilename
    encrypted JSON file to perform the action on

    .PARAMETER thumbprint
    Thumbprint (40 chars) of the existing X509 certificate to use while creating a new secrets JSON file

    .PARAMETER maxCellSize
    Max size in chars of the values to filter with while using CSV related commands

    .PARAMETER schemaJsonFilename
    Fullfilename of the JSON schema file to use while validating a secrets JSON file

    .PARAMETER csvFilename
    Fullfilename of the CSV file to perform an action on

    .PARAMETER secretName
    Name of the secret to update

    .PARAMETER secretValue
    Value of the secret to update with

    .PARAMETER interactive
    switch to launch editor to edit secrets after calling -create command (default is $true)

    .PARAMETER delete
    Switch to delete a key/value pair in an existing secrets JSON file

    .EXAMPLE
    winvault -newCert "Winvault key"

    Create a new self-signed X509 certificate whose subject is "Winvault key" into the local Store (Cert:\CurrentUser\My).

    .EXAMPLE
    winvault -create "C:\Users\martin\Documents\mysecretfile.json" "ABCDEF01234567890123ABCDEF01234567890123"

    Create a new JSON file named "C:\Users\martin\Documents\mysecretfile.json" using a X509 certificate stored in the local Store whose thumbprint is ABCDEF01234567890123ABCDEF01234567890123
    This will fail if such X509 certificate doesn't exist.

    .EXAMPLE
    winvault -edit "C:\Users\martin\Documents\mysecretfile.json"

    Edit with your preferred editor the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json"

    .EXAMPLE
    winvault -editCSV "C:\Users\martin\Documents\mysecretfile.json"

    Edit with your preferred CSV editor the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json"

    .EXAMPLE
    winvault -view "C:\Users\martin\Documents\mysecretfile.json"

    View the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json" in the standard output

    .EXAMPLE
    winvault -viewCSV "C:\Users\martin\Documents\mysecretfile.json"

    View as a table (key/value) the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json" in the standard output

    .EXAMPLE
    winvault -encrypt "C:\Users\martin\Documents\mysecretfile.json" -thumbprint ABCDEF01234567890123ABCDEF01234567890123

    Encrypt in-place the content of "C:\Users\martin\Documents\mysecretfile.json" using a X509 certificate stored in the local Store whose thumbprint is ABCDEF01234567890123ABCDEF01234567890123
    "C:\Users\martin\Documents\mysecretfile.json" should be unencrypted.

    .EXAMPLE
    winvault -decrypt "C:\Users\martin\Documents\mysecretfile.json"

    Decrypt in-place the content of "C:\Users\martin\Documents\mysecretfile.json"
    "C:\Users\martin\Documents\mysecretfile.json" should be encrypted.

    .EXAMPLE
    winvault -schemaJSON "C:\Users\martin\Documents\mysecretfile.json" > "C:\Users\martin\Documents\myJsonSchema.json"

    Print on STDOUT the JSON schema associated with "C:\Users\martin\Documents\mysecretfile.json"
    And redirect the output to a file ("C:\Users\martin\Documents\myJsonSchema.json") to use it with -validate switch

    .EXAMPLE
    winvault -validate "C:\Users\martin\Documents\mysecretfile.json" "C:\Users\martin\Documents\myJsonSchema.json"

    Validate the content of "C:\Users\martin\Documents\mysecretfile.json" against the JSON schema defined in "C:\Users\martin\Documents\myJsonSchema.json"
    This makes use of Newtonsoft\Newtonsoft.Json.dll and Newtonsoft\Newtonsoft.Json.Schema.dll.

    .EXAMPLE
    winvault -update "C:\Users\martin\Documents\mysecretfile.json" "password" "aV3rYS3cR3tP4ss0Rd!"

    Create or update a secret named "password" with value "aV3rYS3cR3tP4ss0Rd!

    .EXAMPLE
    [guid]::NewGuid() | winvault -update "C:\Users\martin\Documents\mysecretfile.json" "ApiKey"

    Create or update a secret named "ApiKey" with value from a previous command using pipe

    .EXAMPLE
    winvault -update "C:\Users\martin\Documents\mysecretfile.json" "password" "aV3rYS3cR3tP4ss0Rd!" -whatif

    Will display the change corresponding to the update command without actually performing it
    (this makes more sense when winvault is used by some wrapper scripts!)

    .EXAMPLE
    winvault -updateCSV "C:\Users\martin\Documents\mysecretfile.json" "C:\Users\martin\Documents\myCsvFile.csv"

    Update the content of "C:\Users\martin\Documents\mysecretfile.json" based on "C:\Users\martin\Documents\myCsvFile.csv".
    "C:\Users\martin\Documents\myCsvFile.csv" is a CSV file with lines such as <Secret Name>, <Secret Value>

    .EXAMPLE
    winvault -delete "C:\Users\martin\Documents\mysecretfile.json" "password"

    Delete secret named "password" in "C:\Users\martin\Documents\mysecretfile.json" secrets file.

    .NOTES
    General notes
    #>

    [cmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='newCert')]
        $newCert,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='create')]
        $create,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='edit')]
        $edit,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='editCSV')]
        $editCSV,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='view')]
        $view,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='viewCSV')]
        $viewCSV,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='encrypt')]
        $encrypt,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='decrypt')]
        $decrypt,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='validate')]
        $validate,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='update')]
        $update,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='updateCSV')]
        $updateCSV,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='schemaJSON')]
        $schemaJSON,

        [Switch]
        [Parameter(Mandatory=$true, ParameterSetName='delete')]
        $delete,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='newCert',   Position=1)]
        $subjectName,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='create',    Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='edit',      Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='encrypt',   Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='decrypt',   Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='validate',  Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='update',    Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='updateCSV', Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='schemaJSON', Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='delete',    Position=1)]
        $secretJsonFilename,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='view',      Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='editCSV',   Position=1)]
        [Parameter(Mandatory=$true, ParameterSetName='viewCSV',   Position=1)]
        $filenamePattern,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='create', Position=2)]
        [Parameter(Mandatory=$true, ParameterSetName='encrypt', Position=2)]
        [ValidateLength(40, 40)]
        $thumbprint,

        [int]
        [Parameter(Mandatory=$false, ParameterSetName='viewCSV', Position=2)]
        $maxCellSize = 0,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='validate', Position=2)]
        $schemaJsonFilename,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='updateCSV', Position=2)]
        $csvFilename,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='update', Position=2)]
        [Parameter(Mandatory=$true, ParameterSetName='delete', Position=2)]
        $secretName,

        [string]
        [Parameter(Mandatory=$true, ParameterSetName='update', ValueFromPipeline=$True, Position=3)]
        $secretValue,

        [switch]
        [Parameter(Mandatory=$false, ParameterSetName='create', Position=2)]
        $interactive = $true
    )

    $DEFAULT_STORE_LOCATION = "CurrentUser"

    $GlobalKeyToSecretMapping= @{}

    $keys = [array]$MyInvocation.BoundParameters.Keys
    $action = $keys[0]

    $EDITOR, $EDITOR_PARAMS, $CSVEDITOR, $CSVEDITOR_PARAMS = refreshEditorsPreference

    switch ($action) {
        "newCert" {
            New-SelfSignedCertificate -Subject $subjectName -CertStoreLocation "Cert:\$DEFAULT_STORE_LOCATION\My"
        }

        "create" {
            if(Test-Path $secretJsonFilename) {
              throw "File $secretJsonFilename already exists."
            }
            else {
              Create -secretJsonFilename $secretJsonFilename -thumbprint $thumbprint -interactive:$interactive
            }
        }

        "encrypt" {
            Encrypt -secretJsonFilename $secretJsonFilename -thumbprint $thumbprint
        }

        "decrypt" {
            Decrypt -secretJsonFilename $secretJsonFilename
        }

        "view" {
            View -filenamePattern $filenamePattern
        }

        "viewCSV" {
            ViewCSV -filenamePattern $filenamePattern -maxCellSize $maxCellSize
        }

        "edit" {
            Edit -secretJsonFilename $secretJsonFilename
        }

        "editCSV" {
            EditCSV -filenamePattern $filenamePattern
        }

        "validate" {
            Validate -secretJsonFilename $secretJsonFilename -schemaJsonFilename $schemaJsonFilename
        }

        "update" {
            Update -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue
        }

        "updateCSV" {
            UpdateCSV -secretJsonFilename $secretJsonFilename -csvFilename $csvFilename
        }

        "schemaJSON" {
          GenerateSchemaJSON -secretJsonFilename $secretJsonFilename
        }

        "delete" {
          Delete -secretJsonFilename $secretJsonFilename -secretName $secretName
        }
    }
}

Function refreshEditorsPreference {
  $EnvEDITOR        = Get-ChildItem Env:WINVAULT_EDITOR        -ErrorAction SilentlyContinue
  $EnvEDITOR_PARAMS = Get-ChildItem Env:WINVAULT_EDITOR_PARAMS -ErrorAction SilentlyContinue

  if($EnvEDITOR)        { $EDITOR        = $EnvEDITOR.value        } else { $EDITOR        = $null }
  if($EnvEDITOR_PARAMS) { $EDITOR_PARAMS = $EnvEDITOR_PARAMS.value } else { $EDITOR_PARAMS = $null }

  if(!$EDITOR) {
    $EDITOR = "C:\Program Files (x86)\Notepad++\notepad++.exe"
    $EDITOR_PARAMS = "-multiInst"
  }

  $EnvCSVEDITOR        = Get-ChildItem Env:WINVAULT_CSVEDITOR        -ErrorAction SilentlyContinue
  $EnvCSVEDITOR_PARAMS = Get-ChildItem Env:WINVAULT_CSVEDITOR_PARAMS -ErrorAction SilentlyContinue

  if($EnvCSVEDITOR)        { $CSVEDITOR        = $EnvCSVEDITOR.value        } else { $CSVEDITOR        = $null }
  if($EnvCSVEDITOR_PARAMS) { $CSVEDITOR_PARAMS = $EnvCSVEDITOR_PARAMS.value } else { $CSVEDITOR_PARAMS = $null }

  if(!$CSVEDITOR) {
    $CSVEDITOR = "C:\Program Files (x86)\Rons Place Apps\Rons Editor\Editor.WinGUI.exe"
    $CSVEDITOR_PARAMS = ""
  }

  return $EDITOR, $EDITOR_PARAMS, $CSVEDITOR, $CSVEDITOR_PARAMS
}

Function HashMD5([String] $String,$HashName = "MD5")
{
  $StringBuilder = New-Object System.Text.StringBuilder
  [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object {  [Void]$StringBuilder.Append($_.ToString("x2")) }
  $StringBuilder.ToString()
}

function Create {
    [CmdletBinding()]
    Param(
      [string] $secretJsonFilename,
      [string] $thumbprint,
      [switch] $interactive
    )

    $emptyJsonObject = @{
      "thumbprint" = $thumbprint;
      "isEncrypted" = $false;
      "secrets" = @{}
    }

    $emptyJsonObject | ConvertTo-Json | Set-Content -Path $secretJsonFilename

    if($interactive) {
      Edit -secretJsonFilename $secretJsonFilename
    }
}

function Encrypt {
    [CmdletBinding()]
    Param(
      [string] $secretJsonFilename,
      [string] $outputFilename = '',
      [string] $thumbprint = '',
      [switch] $isDirty = $false
    )

    $secretJsonFileIsDirty = $false

    $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
    $isEncrypted = $jsonObject.isEncrypted

    if($isEncrypted) {
      Write-Host "Secrets JSON file is already encrypted, decrypting it first before encrypting it with new certificate..."
      Decrypt -secretJsonFilename $secretJsonFilename
      $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
      $isEncrypted = $jsonObject.isEncrypted
    }

    if($isEncrypted) {
      throw "'isEncrypted' property should be false before trying to encrypt."
    }

    if(!$thumbprint) {
      $thumbprint = $jsonObject.thumbprint
    }

    if(!$thumbprint) {
      throw "'thumbprint' property not found."
    }

    if($isDirty -or ($thumbprint -and $jsonObject.thumbprint -and ($jsonObject.thumbprint -ne $thumbprint))) {
      $jsonObject.thumbprint = $thumbprint
      $secretJsonFileIsDirty = $true
      Write-Host "Thumbprint has changed, all secrets values will be updated..."  -ForegroundColor Yellow
    }

    if(!(CheckIfCertIsInStore $thumbprint)) {
      throw "SSL cert with thumbprint $thumbprint not found in local store (Cert:\$DEFAULT_STORE_LOCATION\My)."
    }

    $secrets = $jsonObject.secrets

    if(!$secrets) {
      throw "'secrets' property not found."
    }

    foreach($property in $secrets.psobject.properties) {
        if(($outputFilename) -and (!$secretJsonFileIsDirty)) {
          $UniqueKeyForMapping = "${outputFilename}:$($property.name)"
          if($GlobalKeyToSecretMapping.ContainsKey($UniqueKeyForMapping)) {
            $originalProperty = $GlobalKeyToSecretMapping[$UniqueKeyForMapping]
            if($property.value -eq $originalProperty.secretValuePlainText) {
              $property.value = $originalProperty.secretValue
              Continue
            }
          }
        }

        try {
          $property.value = Invoke-ServiceFabricEncryptText -Text $property.value -CertThumbprint $thumbprint -CertStore -StoreLocation $DEFAULT_STORE_LOCATION -StoreName My
        }
        catch [System.Exception] {
          #Write-Host "Exception while encrypting $($property.name)"
          #$ErrorMessage = $_.Exception.Message
          #Write-Host "Exception: $ErrorMessage"
          #Write-Host "Trying something else..."

          # $property.value is too big, splitting it
          $SIZE = 4000
          $buffer = $property.value
          $length = $buffer.Length

          $nbFullParts = [Math]::Floor($length / $SIZE)
          $reminder = $length % $SIZE

          [System.Collections.ArrayList]$encryptedValues = @()

          For ($i=0; $i -lt $nbFullParts; $i++) {
            $currentValue = $buffer.subString($i * $SIZE, $SIZE)
            $currentValueEncrypted = Invoke-ServiceFabricEncryptText -Text $currentValue -CertThumbprint $thumbprint -CertStore -StoreLocation $DEFAULT_STORE_LOCATION -StoreName My
            [void]($encryptedValues.Add($currentValueEncrypted))
          }
          if($reminder -gt 0) {
            $currentValue = $buffer.subString($nbFullParts * $SIZE, $reminder)
            $currentValueEncrypted = Invoke-ServiceFabricEncryptText -Text $currentValue -CertThumbprint $thumbprint -CertStore -StoreLocation $DEFAULT_STORE_LOCATION -StoreName My
            [void]($encryptedValues.Add($currentValueEncrypted))
          }

          $property.value = ($encryptedValues -join '|')
        }
    }

    $jsonObject.isEncrypted = $true

    if(!$outputFilename) {
      $outputFilename = $secretJsonFilename
    }

    $jsonObject | ConvertTo-Json | Set-Content -Path $outputFilename
}

function DecryptSecretsInPlace {
    Param(
        [object] $secrets,
        [string] $secretJsonFilename
    )

    foreach($property in $secrets.psobject.properties) {
      $originalProperty = @{}
      $originalProperty.name        = $property.name
      $originalProperty.secretValue = $property.value

      $buffers = $property.value.split("|")
      $property.value = ""

      For ($i=0; $i -lt $buffers.length; $i++) {
        $cryptedValue = $buffers[$i]
        if($cryptedValue) {
          try {
            $decryptedValue = Invoke-ServiceFabricDecryptText -CipherText $cryptedValue -StoreLocation $DEFAULT_STORE_LOCATION
          }
          catch [System.Exception] {
            Write-Host "Error while opening $secretJsonFilename..."
            $ErrorMessage = $_.Exception.Message
            Write-Host "$ErrorMessage"
            exit 1
          }
        }
        else {
          $decryptedValue = ""
        }

        $property.value += $decryptedValue
      }

      $originalProperty.secretValuePlainText = $property.value
      $UniqueKeyForMapping = "${secretJsonFilename}:$($property.name)"
      $GlobalKeyToSecretMapping[$UniqueKeyForMapping] = $originalProperty
    }
}

function Decrypt {
    [CmdletBinding()]
    Param(
        [string] $secretJsonFilename,
        [string] $outputFilename = ''
    )

    $jsonContentAsObject = Get-JSonContentAsObject $secretJsonFilename
    $jsonObject = $jsonContentAsObject[1]

    if(!$outputFilename) {
      $outputFilename = $secretJsonFilename
    }

    $jsonObject | ConvertTo-Json | Set-Content -Path $outputFilename
}

function View {
    [CmdletBinding()]
    Param(
        [string] $filenamePattern
    )

    $jsonFileList = Get-ChildItem -Path $filenamePattern

    foreach($jsonFile in $jsonFileList) {
      $secretJsonFilename = $jsonFile.FullName
      $jsonContentAsObject = Get-JSonContentAsObject $secretJsonFilename
      $jsonObject = $jsonContentAsObject[1]
      $jsonObject | ConvertTo-Json
    }
}

function Edit {
    [CmdletBinding()]
    Param(
        [string] $secretJsonFilename
    )

    if(!(Test-Path $EDITOR)) {
      Write-Error "Configured editor executable not found."
      Write-Error "Please check and configure corresponding environment variables: WINVAULT_EDITOR and WINVAULT_EDITOR_PARAMS"
      Write-Error "Current values:"
      Write-Error "WINVAULT_EDITOR = $EDITOR"
      Write-Error "WINVAULT_EDITOR_PARAMS = $EDITOR_PARAMS"
      Write-Error "You can do it globally using the System settings or use Powershell as below:"
      Write-Error '$Env:WINVAULT_EDITOR = <location of the editor executable>'
      Write-Error '$Env:WINVAULT_EDITOR = <parameters to use>'
      Write-Error "For example, you can use these commands for Visual Studio code (default install)"
      Write-Error '$Env:WINVAULT_EDITOR = "C:\Program Files (x86)\Microsoft VS Code\Code.exe"'
      Write-Error '$Env:WINVAULT_EDITOR_PARAMS = "--new-window --wait"'
    }

    $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
    $thumbprint = $jsonObject.thumbprint

    if(!$thumbprint) {
      throw "'thumbprint' property not found."
    }

    $isEncrypted = $jsonObject.isEncrypted

    if($isEncrypted) {
      $outputFilename = [System.IO.Path]::GetTempFileName()
      Decrypt $secretJsonFilename -outputFilename $outputFilename
      $initialHash = (Get-FileHash $outputFilename).hash
      if($EDITOR_PARAMS) {
        Start-Process $EDITOR -ArgumentList @($outputFilename, $EDITOR_PARAMS) -Wait
      }
      else {
        Start-Process $EDITOR -ArgumentList $outputFilename -Wait
      }

      $newHash = (Get-FileHash $outputFilename).hash

      if($newHash -ne $initialHash) {
        Write-Host "Content has been changed, updating..."  -ForegroundColor Yellow
        $jsonNewObject = Get-Content -Raw -Path $outputFilename | ConvertFrom-Json
        if($jsonNewObject.thumbprint -ne $thumbprint) {
          Encrypt $outputFilename -outputFilename $secretJsonFilename -isDirty:$true
        }
        else {
          Encrypt $outputFilename -outputFilename $secretJsonFilename
        }
      }
      else {
        Write-Host "Content has NOT been changed." -ForegroundColor Green
      }
      Remove-Item $outputFilename
    }
    else {
      Start-Process $EDITOR -ArgumentList @($secretJsonFilename, $EDITOR_PARAMS) -Wait
      Encrypt $secretJsonFilename -thumbprint $thumbprint
    }
}

function Get-JSonContentAsObject {
    [CmdletBinding()]
    [OutputType([Object[]])]
    Param(
        [string] $secretJsonFilename
    )

    $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
    $thumbprint = $jsonObject.thumbprint

    if(!$thumbprint) {
      throw "'thumbprint' property not found."
    }

    $isEncrypted = $jsonObject.isEncrypted

    if(!$isEncrypted) {
      throw "'isEncrypted' property should be true before trying to view."
    }

    if(!(CheckIfCertIsInStore $thumbprint)) {
      throw "SSL cert with thumbprint $thumbprint not found in local store (Cert:\$DEFAULT_STORE_LOCATION\My)."
    }

    $secrets = $jsonObject.secrets

    if(!$secrets) {
      throw "'secrets' property not found."
    }

    DecryptSecretsInPlace $secrets $secretJsonFilename

    $jsonObject.isEncrypted = $false

    $properties = @{}

    foreach($property in $secrets.psobject.properties) {
      $properties[$property.Name] = $property.value
    }

    return @($secretJsonFilename, $jsonObject, $properties)
}

<#
$filenamePattern can be a mix of * and/or ?:
"folder\name.*-*.json"
"..\folder\name-???a.json"
#>
function ViewCSV {
    [CmdletBinding()]
    Param(
      [string] $filenamePattern,
      [int] $maxCellSize = 0
    )

    if($maxCellSize -gt 0) {
      $csvResults = DecryptToCSV -filenamePattern $filenamePattern -maxCellSize $maxCellSize
    }
    else {
      $csvResults = DecryptToCSV -filenamePattern $filenamePattern
    }

    $allCsvLines = $csvResults[1]
    $allCsvLines | Format-Table
}

function DecryptToCSV {
  [CmdletBinding()]
  [OutputType([Hashtable],[Object[]])]
    Param(
      [string] $filenamePattern,
      [int]$maxCellSize = 0
    )

    $jsonFileList = Get-ChildItem -Path $filenamePattern -Recurse

    $allPropertyKeys = @()
    $AllJSonContentAsObjectByJsonFile= @{}

    foreach($jsonFile in $jsonFileList) {
      $jsonContentAsObject = Get-JSonContentAsObject $jsonFile.FullName
      $AllJSonContentAsObjectByJsonFile[$jsonFile.Name] = $jsonContentAsObject
      $properties = $jsonContentAsObject[2]
      $allPropertyKeys = [array]($allPropertyKeys + $properties.Keys | Select-Object -uniq)
    }

    $allPropertyKeys = $allPropertyKeys | Sort-Object
    $allCsvLines = @()

    foreach($propertyKey in $allPropertyKeys) {
      $cellTooLong = $false
      $csvLine = new-object PSObject
      $csvLine | add-member -membertype NoteProperty -name "Secret Name" -value $propertyKey
      foreach($jsonFile in $jsonFileList) {
        $jsonContentAsObject = $AllJSonContentAsObjectByJsonFile[$jsonFile.Name]
        $properties = $properties = $jsonContentAsObject[2]
        if($properties.ContainsKey($propertyKey)) {
          $propertyValue = $properties[$propertyKey]
          if(($maxCellSize -gt 0) -and ($propertyValue.Length -gt $maxCellSize)) {
            $cellTooLong = $true
            break
          }
        }
        else {
          $propertyValue = "FIXME"
        }
        $csvLine | add-member -membertype NoteProperty -name $jsonFile.Name -value $propertyValue
      }
      if(!$cellTooLong) {
        $allCsvLines += $csvLine
      }
    }

    return @($AllJSonContentAsObjectByJsonFile, $allCsvLines)
}

function UpdateCSV {
  [CmdletBinding()]
    Param(
        [string] $secretJsonFilename,
        [string] $csvFilename
    )

  Write-Host "Checking if $secretJsonFilename has to be updated..."

  $jsonContentAsObject = Get-JSonContentAsObject $secretJsonFilename
  $properties = $jsonContentAsObject[2]
  $csvLines = Import-Csv $csvFilename

  $propertiesToKeep = @()

  foreach($csvLine in $csvLines) {
    $shouldUpdate = $false

    # use only first 2 columns ('Secret Name', 'Secret Value')
    $index = 0
    foreach($property in $csvLine.psobject.properties) {
      if($index -eq 0) { $propertyName  = $property.Value }
      if($index -eq 1) { $propertyValue = $property.Value }
      $index += 1
    }

    if($properties.ContainsKey($propertyName)) {
      if($properties[$propertyName] -ne $propertyValue) {
        $shouldUpdate = $true
      }
    }
    else {
      $shouldUpdate = $true
    }
    if($shouldUpdate) {
      Update $secretJsonFilename $propertyName $propertyValue
    }
    $propertiesToKeep += $propertyName
  }

  foreach($propertyName in $properties.Keys) {
    if(!($propertyName -in $propertiesToKeep)) {
      Delete $secretJsonFilename $propertyName
    }
  }
}

function EditCSV {
    [CmdletBinding()]
    Param(
      [string] $filenamePattern
    )

    if(!(Test-Path $CSVEDITOR)) {
      Write-Error "Configured CSV editor executable not found."
      Write-Error "Please check and configure corresponding environment variables: WINVAULT_CSVEDITOR and WINVAULT_CSVEDITOR_PARAMS"
      Write-Error "Current values:"
      Write-Error "WINVAULT_CSVEDITOR = $EDITOR"
      Write-Error "WINVAULT_CSVEDITOR_PARAMS = $EDITOR_PARAMS"
      Write-Error "You can do it globally using the System settings or use Powershell as below:"
      Write-Error '$Env:WINVAULT_CSVEDITOR = <location of the editor executable>'
      Write-Error '$Env:WINVAULT_CSVEDITOR = <parameters to use>'
      Write-Error "For example, you can use these commands for Rons editor (default install)"
      Write-Error '$Env:WINVAULT_CSVEDITOR = "C:\Program Files (x86)\Rons Place Apps\Rons Editor\Editor.WinGUI.exe"'
      Write-Error '$Env:WINVAULT_CSVEDITOR_PARAMS = ""'
    }

    $csvResults = DecryptToCSV -filenamePattern $filenamePattern

    $tmpFilename = [System.IO.Path]::GetTempFileName()
    $outputFilename = "$tmpFilename.csv"

    $currentCsvLines = $csvResults[1]
    $currentCsvLines | Export-Csv -Path $outputFilename -notypeinformation -WhatIf:$false
    $initialHash = (Get-FileHash $outputFilename).hash
    Start-Process $CSVEDITOR -ArgumentList @($outputFilename) -Wait
    $newHash = (Get-FileHash $outputFilename).hash
    if($newHash -ne $initialHash) {
        Write-Host "CSV Content has been changed, updating..." -ForegroundColor Yellow
        $newCsvLines = Import-Csv $outputFilename
        $jsonFileList = Get-ChildItem -Path $filenamePattern -Recurse
        foreach($jsonFile in $jsonFileList) {
          $tmpFilename = [System.IO.Path]::GetTempFileName()
          $outputFilenameCurrentFile = "$tmpFilename.csv"
          $newCsvLinesCurrentFile = $newCsvLines | Select-Object "Secret Name", "$($jsonFile.Name)"
          $newCsvLinesCurrentFile | Export-Csv -Path $outputFilenameCurrentFile -notypeinformation -WhatIf:$false
          updateCSV $jsonFile $outputFilenameCurrentFile
          Remove-Item $outputFilenameCurrentFile -WhatIf:$false
        }
    }
    else {
      Write-Host "Content has NOT been changed." -ForegroundColor Green
    }
    Remove-Item $outputFilename -WhatIf:$false
}

function CheckIfCertIsInStore {
    Param(
        [string] $Thumbprint
    )

    $cert = Get-ChildItem "cert:\$DEFAULT_STORE_LOCATION\my" | Where-Object {$_.Thumbprint -eq "${Thumbprint}"}

    return ($null -ne $cert)
}

function Validate {
  [CmdletBinding()]
  Param(
    [string] $secretJsonFilename,
    [string] $schemaJsonFilename
  )

  $NewtonsoftJsonAssemblyPath       = Join-Path -Path $PSScriptRoot -ChildPath 'Newtonsoft\Newtonsoft.Json.dll'
  $NewtonsoftJsonSchemaAssemblyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Newtonsoft\Newtonsoft.Json.Schema.dll'

  Add-Type -Path $NewtonsoftJsonAssemblyPath
  Add-Type -Path $NewtonsoftJsonSchemaAssemblyPath

  $outputFilename = [System.IO.Path]::GetTempFileName()
  Decrypt $secretJsonFilename -outputFilename $outputFilename

  $json       = Get-Content -Raw -Path $outputFilename
  $schemaJson = Get-Content -Raw -Path $schemaJsonFilename

  try {
    [Newtonsoft.Json.Schema.SchemaExtensions]::Validate([Newtonsoft.Json.Linq.JToken]::Parse($json), [Newtonsoft.Json.Schema.JSchema]::Parse($schemaJson))
  }
  catch [System.Exception] {
    $ErrorMessage = $_.Exception.Message
    Write-Host "Error while validating JSon file against Schema: $ErrorMessage" -ForegroundColor Red
  }
  finally {
    Remove-Item $outputFilename
  }
}

function Update {
  [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
      [string] $secretJsonFilename,
      [string] $secretName,
      [string] $secretValue
    )

    $jsonObject = view -filenamePattern $secretJsonFilename | ConvertFrom-Json
    $secrets = $jsonObject.secrets

    $propertyExists = $false
    $contentChanged = $false

    foreach($property in $secrets.psobject.properties) {
      if($property.Name -eq $secretName) {
        $propertyExists = $true
        Write-Host "Secret $secretName already exists"
        if($property.value -eq $secretValue) {
          $hash = HashMD5 $secretValue
          Write-Host "Secret value is already the right one (hash=$hash), nothing to do." -ForegroundColor Green
        }
        else {
          if ($pscmdlet.ShouldProcess("Updating secret value...", "Update")) {
            Write-Host "Updating secret value..." -ForegroundColor Yellow
            $property.value  = $secretValue
            $contentChanged = $true
          }
        }

        break
      }
    }

    if(!$propertyExists) {
      if ($pscmdlet.ShouldProcess("Adding new secret '$secretName'...", "Update")) {
        Write-Host "Adding new secret '$secretName'..." -ForegroundColor Yellow
        $secrets | Add-Member -NotePropertyName $secretName -NotePropertyValue $secretValue
        $contentChanged = $true
      }
    }

    if($contentChanged) {
      Write-Host "Content has been changed, updating..." -ForegroundColor Yellow
      $outputFilename = [System.IO.Path]::GetTempFileName()
      $jsonObject | ConvertTo-Json | Set-Content -Path $outputFilename

      #$jsonObject | ConvertTo-Json

      #Start-Process $EDITOR -ArgumentList @($outputFilename, $EDITOR_PARAMS) -Wait

      Encrypt $outputFilename -outputFilename $secretJsonFilename
      Remove-Item $outputFilename
    }
    else {
      Write-Host "Content has NOT been changed." -ForegroundColor Green
    }
}

function generateSchemaJSON {
  [CmdletBinding()]
  Param(
    [string] $secretJsonFilename
  )

  $jsonContentAsObject = Get-JSonContentAsObject $secretJsonFilename
  $properties = $jsonContentAsObject[2]

  $jsonSchemaAsObject = [ordered]@{}
  $jsonSchemaAsObject['$schema'] = "http://json-schema.org/draft-06/schema#"
  $jsonSchemaAsObject['description'] = "JSON schema for secrets JSON files"
  $jsonSchemaAsObject['type'] = "object"
  $jsonSchemaAsObject['required'] = @("isEncrypted", "thumbprint", "secrets")
  $jsonSchemaAsObject['additionalProperties'] = $true

  $propertiesForSecrets = [ordered]@{}
  $properties.Keys | foreach  { $propertiesForSecrets[$_] =  [ordered]@{"description" = "FIXME"; "type" = "string" } }

  $jsonSchemaAsObject['properties'] = [ordered]@{
    "isEncrypted" = [ordered]@{
      "type" = "boolean"
    }
    "thumbprint" = [ordered] @{
      "description" = "Thumprint of SSL certificate to use for encryption/decryption"
      "type" = "string"
    }
    "secrets" = [ordered]@{
      "description" = "Secrets as properties"
      "type" = "object"
      "required" = $properties.Keys
      "additionalProperties" = $false
      "properties" = $propertiesForSecrets
    }
  }

  $jsonSchemaAsObject |  ConvertTo-Json -Depth 10
}

function Delete {
  [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
      [string] $secretJsonFilename,
      [string] $secretName
    )

    $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
    $secrets = $jsonObject.secrets

    $propertyExists = $false

    foreach($property in $secrets.psobject.properties) {
      if($property.Name -eq $secretName) {
        $propertyExists = $true
        break
      }
    }

    if($propertyExists) {
      if ($pscmdlet.ShouldProcess("Deleting secret '$secretName'...", "Delete")) {
        Write-Host "Deleting secret '$secretName'..." -ForegroundColor Yellow
        $secrets.psobject.properties.Remove($secretName)
        Write-Host "Content has been changed, updating..." -ForegroundColor Yellow
        $jsonObject | ConvertTo-Json | Set-Content -Path $secretJsonFilename
      }
    }
    else {
      Write-Host "Secret $secretName not found."
      Write-Host "Content has NOT been changed." -ForegroundColor Green
    }
}

Export-ModuleMember -Function winvault