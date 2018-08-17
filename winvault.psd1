@{

RootModule = '.\winvault.psm1'

ModuleVersion = '1.0.0'


# CompatiblePSEditions = @()

GUID = 'd24312bd-8e53-4eaa-819c-f4d1914508f7'
Author = 'sebbrochet'
CompanyName = 'cloudenza'
Copyright = 'Copyright (c) 2018 by Cloudenza, licensed under Apache 2.0 License.'

Description = 'winvault is a complete solution to manage the lifecycle of your secrets as key/value pairs into encrypted JSON files. It uses X509 certificates stored in your computer to do the encryption. As the files are encrypted they can be stored and versioned into git.'

PowerShellVersion = '5.1'

RequiredModules = @('ServiceFabric')

FunctionsToExport = 'winvault'

CmdletsToExport = @()

AliasesToExport = @()

PrivateData = @{
    PSData = @{
        Category = "Scripting Techniques"

        Tags = @('winvault', 'powershell', 'cryptography', 'Secret', 'git')

        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0'

        ProjectURI='https://github.com/sebbrochet/winvault'

    }

}

# HelpInfoURI = 'FIXME'
}

