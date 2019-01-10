winvault
===============

[![Build Status](https://img.shields.io/appveyor/ci/sebbrochet/winvault.svg)](https://ci.appveyor.com/project/sebbrochet/winvault)
[![Test Status](https://img.shields.io/appveyor/tests/sebbrochet/winvault.svg)](https://ci.appveyor.com/project/sebbrochet/winvault/build/tests)

winvault is a complete solution to manage the lifecycle of your secrets as key/value pairs into encrypted JSON files.  
It uses X509 certificates stored in your computer to do the encryption.   
As the files are encrypted they can be stored and versioned into git.  

## Installation
* Clone or download this repository

  * To give it a try in your local Powershell session
  ```powershell
  Import-Module .\winvault.psd1
  ```

  * To install it permanently on your system (not supported yet, waiting to publish to powershellgallery.com when ready)
  ```powershell
  Install-Module -Name winvault -Scope CurrentUser -Force -SkipPublisherCheck
  ```

### Usage
* Type ```get-help winvault``` to display syntax as below

```
SYNTAX
    winvault -newCert [-subjectName] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -create [-secretJsonFilename] <String> [-thumbprint] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -edit [-secretJsonFilename] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -editCSV [-filenamePattern] <String> [[-maxCellSize] <Int32>] [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -view [-filenamePattern] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -viewCSV [-filenamePattern] <String> [[-maxCellSize] <Int32>] [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -encrypt [-secretJsonFilename] <String> [-thumbprint] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -decrypt [-secretJsonFilename] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -validate [-secretJsonFilename] <String> [-schemaJsonFilename] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -update [-secretJsonFilename] <String> [-secretName] <String> [-secretValue] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -updateCSV [-secretJsonFilename] <String> [-csvFilename] <String> [-WhatIf] [-Confirm] [<CommonParameters>]

    winvault -schemaJSON [-secretJsonFilename] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## Examples
* Type ```get-help winvault -examples``` to display examples as below

```
-------------------------- EXEMPLE 1 --------------------------

    PS C:\>winvault -newCert "Winvault key"

    Create a new self-signed X509 certificate whose subject is "Winvault key" into the local Store (Cert:\CurrentUser\My).




    -------------------------- EXEMPLE 2 --------------------------

    PS C:\>winvault -create "C:\Users\martin\Documents\mysecretfile.json" "ABCDEF01234567890123ABCDEF01234567890123"

    Create a new JSON file named "C:\Users\martin\Documents\mysecretfile.json" using a X509 certificate stored in the local Store whose thumbprint is ABCDEF01234567890123ABCDEF01234567890123
    This will fail if such X509 certificate doesn't exist.




    -------------------------- EXEMPLE 3 --------------------------

    PS C:\>winvault -edit "C:\Users\martin\Documents\mysecretfile.json"

    Edit with your preferred editor the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json"




    -------------------------- EXEMPLE 4 --------------------------

    PS C:\>winvault -editCSV "C:\Users\martin\Documents\mysecretfile.json"

    Edit with your preferred CSV editor the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json"




    -------------------------- EXEMPLE 5 --------------------------

    PS C:\>winvault -view "C:\Users\martin\Documents\mysecretfile.json"

    View the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json" in the standard output




    -------------------------- EXEMPLE 6 --------------------------

    PS C:\>winvault -viewCSV "C:\Users\martin\Documents\mysecretfile.json"

    View as a table (key/value) the unencrypted content of "C:\Users\martin\Documents\mysecretfile.json" in the standard output




    -------------------------- EXEMPLE 7 --------------------------

    PS C:\>winvault -encrypt "C:\Users\martin\Documents\mysecretfile.json"

    Encrypt in-place the content of "C:\Users\martin\Documents\mysecretfile.json"
    "C:\Users\martin\Documents\mysecretfile.json" should be unencrypted.




    -------------------------- EXEMPLE 8 --------------------------

    PS C:\>winvault -decrypt "C:\Users\martin\Documents\mysecretfile.json"

    Decrypt in-place the content of "C:\Users\martin\Documents\mysecretfile.json"
    "C:\Users\martin\Documents\mysecretfile.json" should be encrypted.




    -------------------------- EXEMPLE 9 --------------------------

    winvault -schemaJSON "C:\Users\martin\Documents\mysecretfile.json" >"C:\Users\martin\Documents\myJsonSchema.json"

    Print on STDOUT the JSON schema associated with "C:\Users\martin\Documents\mysecretfile.json"
    And redirect the output to a file ("C:\Users\martin\Documents\myJsonSchema.json") to use it with -validate switch




    -------------------------- EXEMPLE 10 --------------------------

    PS C:\>winvault -validate "C:\Users\martin\Documents\mysecretfile.json"
    "C:\Users\martin\Documents\myJsonSchema.json"

    Validate the content of "C:\Users\martin\Documents\mysecretfile.json" against the JSON schema defined in
    "C:\Users\martin\Documents\myJsonSchema.json"
    This makes use of Newtonsoft\Newtonsoft.Json.dll and Newtonsoft\Newtonsoft.Json.Schema.dll.




    -------------------------- EXEMPLE 11 --------------------------

    PS C:\>winvault -update "C:\Users\martin\Documents\mysecretfile.json" "password" "aV3rYS3cR3tP4ss0Rd!"

    Create or update a secret named "password" with value "aV3rYS3cR3tP4ss0Rd!




    -------------------------- EXEMPLE 12 --------------------------

    PS C:\>[guid]::NewGuid() | winvault -update "C:\Users\martin\Documents\mysecretfile.json" "ApiKey"

    Create or update a secret named "ApiKey" with value from a previous command using pipe




    -------------------------- EXEMPLE 13 --------------------------

    PS C:\>winvault -update "C:\Users\martin\Documents\mysecretfile.json" "password" "aV3rYS3cR3tP4ss0Rd!" -whatif

    Will display the change corresponding to the update command without actually performing it
    (this makes more sense when winvault is used by some wrapper scripts!)




    -------------------------- EXEMPLE 14 --------------------------

    PS C:\>winvault -updateCSV "C:\Users\martin\Documents\mysecretfile.json" "C:\Users\martin\Documents\myCsvFile.csv"

    Update the content of "C:\Users\martin\Documents\mysecretfile.json" based on
    "C:\Users\martin\Documents\myCsvFile.csv".
    "C:\Users\martin\Documents\myCsvFile.csv" is a CSV file with lines such as <Secret Name>, <Secret Value>
```
