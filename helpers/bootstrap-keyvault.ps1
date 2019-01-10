[cmdletBinding(SupportsShouldProcess=$true)]
Param(
    [string]
    [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
    $winvaultSecretsFileAsString,

    [string]
    [Parameter(Mandatory=$true)]
    $vaultName
)

Set-strictmode -version latest
$ErrorActionPreference = 'stop'

$winvaultSecretsFileAsObject = $winvaultSecretsFileAsString | ConvertFrom-Json

foreach($property in $winvaultSecretsFileAsObject.secrets.psobject.properties) {
  $propertyName = $property.Name
  $propertyValue = $property.Value

  $currentSecret = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $propertyName -ErrorAction SilentlyContinue

  if((!$currentSecret) -or ($currentSecret.SecretValueText -ne $propertyValue)) {
    if ($pscmdlet.ShouldProcess("Creating/Updating $propertyName with new value...", "UpdateKv")) {
      $secretValue = ConvertTo-SecureString -String $propertyValue -AsPlainText -Force
      Write-Host "Creating/Updating $propertyName with new value..."
      $secret = Set-AzureKeyVaultSecret -VaultName $VaultName -Name $propertyName -SecretValue $secretValue
    }
  }
  else {
    if ($pscmdlet.ShouldProcess("$propertyName is already up-to-date", "UpdateKv")) {
      Write-Host "$propertyName is already up-to-date"
    }
  }
}