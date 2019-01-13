#requires -Modules Pester

Import-Module $PSScriptRoot\..\src\winvault -Force

Describe "Import-Module winvault" {
  Context "Module Exports" {
    It "Should export at least one function" {
      @(Get-Command -Module winvault).Count | Should BeGreaterThan 0
    }
  }
}

Describe "winvault commands" {
  $PWDLocation = Get-Location

  BeforeEach {
      Set-Location $TestDrive
  }
  AfterEach {
      Set-Location $PWDLocation
  }

  Context "New certificate creation (-newCert)" {
    It "Should create a new SSL certificate and return thumbprint (40 chars)" {
      $cert = winvault -newCert "winvault unit tests"
      $cert.Thumbprint.Length | Should Be 40

      Remove-Item $cert.PSPath
    }
  }

  Context "Create a new secrets file (-create)" {
    It "Should create a new secrets file with no secrets" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      winvault -create -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
      $jsonObject.isEncrypted | Should Be $false
      $jsonObject.thumbprint | Should Be $cert.thumbprint
      ($jsonObject.secrets.psobject.properties | Measure-Object).count | Should Be 0

      Remove-Item $cert.PSPath
    }
  }

  <#
  Context "Create a new secrets file (-create)" {
    It "Should fail while creating a new secrets file if it already exists" {
      $secretJsonFilename = "mysecretfile.json"
      "dummy" | Out-File $secretJsonFilename
      winvault -create -secretJsonFilename $secretJsonFilename -thumbprint "DUMMY" -interactive:$false | Should -Throw "File $secretJsonFilename already exists."

      Remove-Item $cert.PSPath
    }
  }
  #>

  Context "Encrypt a secrets file that is not encrypted (-encrypt)" {
    It "Should encrypt a secrets file (with no secrets)" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      winvault -create -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
      $jsonObject.isEncrypted | Should Be $true
      $jsonObject.thumbprint | Should Be $cert.thumbprint
      ($jsonObject.secrets.psobject.properties | Measure-Object).count | Should Be 0

      $cert2 = winvault -newCert "winvault unit tests"
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert2.thumbprint

      Remove-Item $cert.PSPath
      Remove-Item $cert2.PSPath
    }
  }

  Context "View a secrets file that is encrypted in JSON format (-view)" {
    It "Should view a secrets file (with no secrets)" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      winvault -create -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      $jsonObject = winvault -view -filenamePattern $secretJsonFilename | ConvertFrom-Json
      $jsonObject.isEncrypted | Should Be $false
      $jsonObject.thumbprint | Should Be $cert.thumbprint
      ($jsonObject.secrets.psobject.properties | Measure-Object).count | Should Be 0

      Remove-Item $cert.PSPath
    }
  }

  Context "View a secrets file that is encrypted in table format (-viewCSV)" {
    It "Should view a secrets file (with no secrets)" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      winvault -create -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      $allCsvLines = winvault -viewCSV -filenamePattern $secretJsonFilename
      $allCsvLines.count | Should Be 0

      $allCsvLines = winvault -viewCSV -filenamePattern $secretJsonFilename -maxCellSize 80

      Remove-Item $cert.PSPath
    }
  }

  Context "Decrypt a secrets file (-decrypt)" {
    It "Should decrypt a secrets file" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      winvault -create  -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      winvault -decrypt -secretJsonFilename $secretJsonFilename
      $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
      $jsonObject.isEncrypted | Should Be $false
      $jsonObject.thumbprint | Should Be $cert.thumbprint
      ($jsonObject.secrets.psobject.properties | Measure-Object).count | Should Be 0

      Remove-Item $cert.PSPath
    }
  }

  Context "Update a secrets file (-update)" {
    It "Should update a secrets file" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      $secretName = "Password"
      $secretValue = "s3cr3tV@1u3"
      $secretValue1 = "s3cr3tV@1u3A"
      winvault -create  -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue -WhatIf
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue1 -WhatIf
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue1
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue -WhatIf
      $jsonObject = Get-Content -Raw -Path $secretJsonFilename | ConvertFrom-Json
      $jsonObject.isEncrypted | Should Be $true
      $jsonObject.thumbprint | Should Be $cert.thumbprint
      ($jsonObject.secrets.psobject.properties | Measure-Object).count | Should Be 1

      Remove-Item $cert.PSPath
    }
  }

  Context "Display JSON schema for a secrets file (-schemaJSON)" {
    It "Should display the JSON schema for a secrets file" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      $secretName = "Password"
      $secretValue = "s3cr3tV@1u3"
      winvault -create  -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue
      $jsonObject = winvault -schemaJSON -secretJsonFilename $secretJsonFilename | ConvertFrom-Json

      $jsonObject.'$schema' | Should Be "http://json-schema.org/draft-06/schema#"
      $jsonObject.description | Should Be "JSON schema for secrets JSON files"
      $jsonObject.additionalProperties | Should Be $true
      $jsonObject.required.count | Should Be 3
      "isEncrypted" | Should -BeIn $jsonObject.required
      "thumbprint"  | Should -BeIn $jsonObject.required
      "secrets"     | Should -BeIn $jsonObject.required
      $jsonObject.properties.isEncrypted.type | Should Be "boolean"
      $jsonObject.properties.thumbprint.type | Should Be "string"
      $jsonObject.properties.secrets.type | Should Be "object"
      ($jsonObject.properties.psobject.properties | Measure-Object).count | Should Be 3
      ($jsonObject.properties.secrets.psobject.properties | Measure-Object).count | Should Be 5

      Remove-Item $cert.PSPath
    }
  }

  <#
  Context "Validate secrets file with a JSON schema (-validate)" {
    It "Should validate the JSON schema for a secrets file" {
      $cert = winvault -newCert "winvault unit tests"
      $secretJsonFilename = "mysecretfile.json"
      $secretName = "Password"
      $secretValue = "s3cr3tV@1u3"
      $schemaJsonFilename = "myJsonSchema.json"
      winvault -create  -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint -interactive:$false
      winvault -encrypt -secretJsonFilename $secretJsonFilename -thumbprint $cert.thumbprint
      winvault -update  -secretJsonFilename $secretJsonFilename -secretName $secretName -secretValue $secretValue
      winvault -schemaJSON -secretJsonFilename $secretJsonFilename | Out-File $schemaJsonFilename
      winvault -validate -secretJsonFilename $secretJsonFilename -schemaJsonFilename $schemaJsonFilename

      Remove-Item $cert.PSPath
    }
  }
  #>

}
