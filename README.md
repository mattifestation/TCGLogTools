# TCGLogTools

TCGLogTools is a set of tools to retrieve and parse TCG measured boot logs. Microsoft refers to these as Windows Boot Confirguration Logs (WBCL). In order to retrieve these logs, you must be running at least Windows 8 with the TPM enabled.

TCG logs are extremely useful because measurements (and relevant context with TPM 2.0) are logged throughout all stages of the OS boot process. The logs are intended to be used for device attestation purposes but they can also be used for incedent response where it is suspected that boot/OS explotiation/configuration changes occured.

## TCG Log Retrieval

Unparsed TCG logs (also referred to as Measured Boot logs) content can be retrieved with the `Get-TCGLogContent` function. Here are some examples retrieving the log contents:

```powershell
Get-TCGLogContent -LogType SRTMBoot
```
This retrieves the log contents for the last clean boot. Under the hood, this pulls the most recent log from `%windir%\Logs\MeasuredBoot\[BootCount]-0000000000.log`.

```powershell
Get-TCGLogContent -LogType SRTMCurrent
```
This retrieves the most recent measured boot log contents directly from the registry: `HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL`

```powershell
Get-TCGLogContent -LogType SRTMResume
```

This retrieves the log after the first resume state after a clean boot. This option can be used to compare if any PCR measurements were different between the current OS state and the last resume state, which if there were a difference, it might warrant investigation.

Logs may also be retrieved directly from `%windir%\Logs\MeasuredBoot\` using `Get-ChildItem` and piping the output to `ConvertTo-TCGEventLog`.

## TCG Log Parsing

Once the contents of one or more TCG logs is obtained, `ConvertTo-TCGEventLog` does the work of parsing the log. Here are some example use cases:

```powershell
$TCGLogBytes = Get-TCGLogContent -LogType SRTMCurrent
$TCGLog = ConvertTo-TCGEventLog -LogBytes $TCGLogBytes
```
This parses out the most current TCG log.

```powershell
ls C:\Windows\Logs\MeasuredBoot\*.log | ConvertTo-TCGEventLog
```
This parses the contents of all TCG logs.

```powershell
ConvertTo-TCGEventLog -LogPath 'C:\Windows\Logs\MeasuredBoot\0000000001-0000000000.log'
```
This parses a specific TCG log.

```powershell
ConvertTo-TCGEventLog -LogBytes (Get-TCGLogContent -LogType SRTMBoot) -MinimizedX509CertInfo | ConvertTo-Json -Depth 8 | Out-File 'TCGlog.json'
```
Sometimes, it may be desirable to view the output of the complex TCG log structure as a JSON file. In that case, it is recommended to supply the `-MinimizedX509CertInfo` in order to minimize excessive output associated with certificate contents.

## Working With Parsed TCG Log Contents

When working with a parsed TCG log, it may be useful to initially group measurements by their respective PCRs so that you can observe what event types are typically associated with different PCR throughout the boot phase.

```powershell
$TCGLogBytes = Get-TCGLogContent -LogType SRTMCurrent
$TCGLog = ConvertTo-TCGEventLog -LogBytes $TCGLogBytes
$TCGLog.Events | Sort PCR | Group PCR
```

You may also want to group events by their event types to see what specific information is availble in each event:

```powershell
$TCGLog.Events | Group EventType
```

Once you work with the data enough, you should start getting a sense of how to diff data across TCG logs. What follows are several incident response scenarios where TCg logs were compared across reboots for evidence of suspicious activity.

### Malicious Scenario #1: SecureBoot Disabled
I deliberately disabled SecureBoot in the UEFI BIOS so that I could observe the measurement differences. Upon disabling SecureBoot, upon the next reboot, I compared the latest clean boot log (0000000030-0000000000.log) to the clean boot log from the previous boot (0000000029-0000000000.log). Using `ConvertTo-TCGEventLog` on both logs, I could observe that there was a difference in the following PCR7 (i.e. those related to SecureBoot) measurements:

1. The PCR7 EV_EFI_VARIABLE_DRIVER_CONFIG event value for the "SecureBoot" UEFI variable goes from 1 (enabled) to 0 (disabled). The variable digest values differed as well.
2. 0000000030-0000000000.log has one less PCR7 (SecureBoot) measurement: it doesn't have an EV_EFI_VARIABLE_AUTHORITY event (which should follow the EV_SEPARATOR event).

### Malicious Scenario #2: TestSigning Enabled to Circumvent Driver Signature Enforcement

BLAH BLAH BLAH

So not only can these logs be used to attest to specific boot states and configurations, but they can also be used to investigate potentially suspicious changes. `ConvertTo-TCGEventLog` can also be used to baseline assumed known-good states. For example, PCR0 measurements should rarely change.

## References

The logic of this parser would not have been possible without the following references:

* [PC Client Platform TPM Profile (PTP) Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
* [UEFI Specification](http://www.uefi.org/specifications)
* [Microsoft TSS.MSR](https://github.com/Microsoft/TSS.MSR)
* wbcl.h in the [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)