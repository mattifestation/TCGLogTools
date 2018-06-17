@{
RootModule = 'TCGLogTools.psm1'

ModuleVersion = '0.2.0.0'

GUID = '39075465-235a-4878-9dcf-301af4feed60'

Author = 'Matthew Graeber'

Copyright = 'BSD 3-Clause'

Description = 'TCGLogTools is a set of tools to retrieve and parse TCG measured boot logs. Microsoft refers to these as Windows Boot Confirguration Logs (WBCL). In order to retrieve these logs, you must be running at least Windows 8 with the TPM enabled.'

PowerShellVersion = '3.0'

# Functions to export from this module
FunctionsToExport = @(
    'Get-TCGLogContent',
    'ConvertTo-TCGEventLog',
    'Get-TPMDeviceInfo'
)

PrivateData = @{

    PSData = @{
        Tags = @('security', 'DFIR', 'defense')

        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        ProjectUri = 'https://github.com/mattifestation/TCGLogTools'

        ReleaseNotes = @'
0.2.0
Enhancements:
* Major refactor of ConvertTo-TCGEventLog output. Parsed logs are much more intuitive now.

0.1.0
-----
Initial release!

Enhancements:
* Added Get-TCGLogContent, ConvertTo-TCGEventLog, and Get-TPMDeviceInfo
'@
    }

}

}
