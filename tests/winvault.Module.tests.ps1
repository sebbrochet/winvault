Import-Module $PSScriptRoot\..\\winvault -Force

Describe "Import-Module winvault" {
  Context "Module Exports" {
    It "Should export at least one function" {
      @(Get-Command -Module winvault).Count | Should BeGreaterThan 0
    }
  }
}
