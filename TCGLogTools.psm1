# APIs required to interface with the TPM service
Add-Type -ErrorAction Stop -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;

    namespace TPMBaseServices {
        public enum TPM_VERSION {
            TPM_VERSION_UNKNOWN = 0,
            TPM_VERSION_12,
            TPM_VERSION_20
        }

        public enum TPM_IFTYPE : uint {
            TPM_IFTYPE_UNKNOWN = 0,
            TPM_IFTYPE_1,
            TPM_IFTYPE_TRUSTZONE,
            TPM_IFTYPE_HW,
            TPM_IFTYPE_EMULATOR,
            TPM_IFTYPE_SPB
        }

        public enum TBS_TCGLOG : uint {
            TBS_TCGLOG_SRTM_CURRENT = 0,
            TBS_TCGLOG_DRTM_CURRENT,
            TBS_TCGLOG_SRTM_BOOT,
            TBS_TCGLOG_SRTM_RESUME
        }

        public struct TPM_DEVICE_INFO {
            public uint structVersion;
            public TPM_VERSION tpmVersion;
            public TPM_IFTYPE tpmInterfaceType;
            public uint tpmImpRevision;
        }

        public class UnsafeNativeMethods {
            [DllImport("tbs.dll")]
            public static extern uint Tbsi_GetDeviceInfo(ulong Size, out TPM_DEVICE_INFO Info);

            // This API is much more flexible than Tbsi_Get_TCG_Log because you don't need to get a TBS context.
            [DllImport("tbs.dll")]
            public static extern uint Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG logType, IntPtr pOutputBuf, ref uint OutputBufLen);
        }
    }
'@

#region: enums required for multiple functions

# Used to display friendly error messages if a TBS function fails.
$Script:TBSReturnCodes = @{
    ([UInt32] 2150121473) = 'An internal software error occurred.'
    ([UInt32] 2150121474) = 'One or more parameter values are not valid.'
    ([UInt32] 2150121475) = 'A specified output pointer is bad.'
    ([UInt32] 2150121476) = 'The specified context handle does not refer to a valid context.'
    ([UInt32] 2150121477) = 'The specified output buffer is too small.'
    ([UInt32] 2150121478) = 'An error occurred while communicating with the TPM.'
    ([UInt32] 2150121479) = 'A context parameter that is not valid was passed when attempting to create a TBS context.'
    ([UInt32] 2150121480) = 'The TBS service is not running and could not be started.'
    ([UInt32] 2150121481) = 'A new context could not be created because there are too many open contexts.'
    ([UInt32] 2150121482) = 'A new virtual resource could not be created because there are too many open virtual resources.'
    ([UInt32] 2150121483) = 'The TBS service has been started but is not yet running.'
    ([UInt32] 2150121484) = 'The physical presence interface is not supported.'
    ([UInt32] 2150121485) = 'The command was canceled.'
    ([UInt32] 2150121486) = 'The input or output buffer is too large.'
    ([UInt32] 2150121487) = 'A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.'
    ([UInt32] 2150121488) = 'The TBS service has been disabled.'
    ([UInt32] 2150121489) = 'The TBS event log is not available.'
    ([UInt32] 2150121490) = 'The caller does not have the appropriate rights to perform the requested operation.'
    ([UInt32] 2150121491) = 'The TPM provisioning action is not allowed by the specified flags.'
    ([UInt32] 2150121492) = 'The Physical Presence Interface of this firmware does not support the requested method.'
    ([UInt32] 2150121493) = 'The requested TPM OwnerAuth value was not found.'
    # 2150121493 may be a typo in the docs for the below return code. Need to reverse tbs.dll to confirm
    ([UInt32] 2150121494) = "The TPM provisioning did not complete. For more information on completing the provisioning, call the Win32_Tpm WMI method for provisioning the TPM ('Provision') and check the returned information."
}

# Obtained from wbcl.h in the WDK
# These refer to Windows-specific data types for PCR 12-14 and -1 (TrustPoint)
$Script:SIPAEventMapping = @{
    # SIPAEVENTTYPE_CONTAINER
    # All of these types will contain embedded event data
    0x40010001 = 'TrustBoundary'                   # SIPAEVENT_TRUSTBOUNDARY
    0x40010002 = 'ELAMAggregation'                 # SIPAEVENT_ELAM_AGGREGATION
    0x40010003 = 'LoadedModuleAggregation'         # SIPAEVENT_LOADEDMODULE_AGGREGATION
    0xC0010004 = 'TrustpointAggregation'           # SIPAEVENT_TRUSTPOINT_AGGREGATION
    0x40010005 = 'KSRAggregation'                  # SIPAEVENT_KSR_AGGREGATION
    0x40010006 = 'KSRSignedMeasurementAggregation' # SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION

    # SIPAEVENTTYPE_INFORMATION
    0x00020001 = 'Information'         # SIPAEVENT_INFORMATION
    0x00020002 = 'BootCounter'         # SIPAEVENT_BOOTCOUNTER
    0x00020003 = 'TransferControl'     # SIPAEVENT_TRANSFER_CONTROL
    0x00020004 = 'ApplicationReturn'   # SIPAEVENT_APPLICATION_RETURN
    0x00020005 = 'BitlockerUnlock'     # SIPAEVENT_BITLOCKER_UNLOCK
    0x00020006 = 'EventCounter'        # SIPAEVENT_EVENTCOUNTER
    0x00020007 = 'CounterID'           # SIPAEVENT_COUNTERID
    0x00020008 = 'MORBitNotCancelable' # SIPAEVENT_MORBIT_NOT_CANCELABLE
    0x00020009 = 'ApplicationSVN'      # SIPAEVENT_APPLICATION_SVN
    0x0002000A = 'SVNChainStatus'      # SIPAEVENT_SVN_CHAIN_STATUS
    0x0002000B = 'MORBitAPIStatus'     # SIPAEVENT_MORBIT_API_STATUS

    # SIPAEVENTTYPE_PREOSPARAMETER
    0x00040001 = 'BootDebugging'       # SIPAEVENT_BOOTDEBUGGING
    0x00040002 = 'BootRevocationList'  # SIPAEVENT_BOOT_REVOCATION_LIST

    # SIPAEVENTTYPE_OSPARAMETER
    0x00050001 = 'OSKernelDebug'             # SIPAEVENT_OSKERNELDEBUG
    0x00050002 = 'CodeIntegrity'             # SIPAEVENT_CODEINTEGRITY
    0x00050003 = 'TestSigning'               # SIPAEVENT_TESTSIGNING
    0x00050004 = 'DataExecutionPrevention'   # SIPAEVENT_DATAEXECUTIONPREVENTION
    0x00050005 = 'SafeMode'                  # SIPAEVENT_SAFEMODE
    0x00050006 = 'WinPE'                     # SIPAEVENT_WINPE
    0x00050007 = 'PhysicalAddressExtension'  # SIPAEVENT_PHYSICALADDRESSEXTENSION
    0x00050008 = 'OSDevice'                  # SIPAEVENT_OSDEVICE
    0x00050009 = 'SystemRoot'                # SIPAEVENT_SYSTEMROOT
    0x0005000A = 'HypervisorLaunchType'      # SIPAEVENT_HYPERVISOR_LAUNCH_TYPE
    0x0005000B = 'HypervisorPath'            # SIPAEVENT_HYPERVISOR_PATH
    0x0005000C = 'HypervisorIOMMUPolicy'     # SIPAEVENT_HYPERVISOR_IOMMU_POLICY
    0x0005000D = 'HypervisorDebug'           # SIPAEVENT_HYPERVISOR_DEBUG
    0x0005000E = 'DriverLoadPolicy'          # SIPAEVENT_DRIVER_LOAD_POLICY
    0x0005000F = 'SIPolicy'                  # SIPAEVENT_SI_POLICY
    0x00050010 = 'HypervisorMMIONXPolicy'    # SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY
    0x00050011 = 'HypervisorMSRFilterPolicy' # SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY
    0x00050012 = 'VSMLaunchType'             # SIPAEVENT_VSM_LAUNCH_TYPE
    0x00050013 = 'OSRevocationList'          # SIPAEVENT_OS_REVOCATION_LIST
    0x00050020 = 'VSMIDKInfo'                # SIPAEVENT_VSM_IDK_INFO
    0x00050021 = 'FlightSigning'             # SIPAEVENT_FLIGHTSIGNING
    0x00050022 = 'PagefileEncryptionEnabled' # SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED
    0x00050023 = 'VSMIDKSInfo'               # SIPAEVENT_VSM_IDKS_INFO
    0x00050024 = 'HibernationDisabled'       # SIPAEVENT_HIBERNATION_DISABLED
    0x00050025 = 'DumpsDisabled'             # SIPAEVENT_DUMPS_DISABLED
    0x00050026 = 'DumpEncryptionEnabled'     # SIPAEVENT_DUMP_ENCRYPTION_ENABLED
    0x00050027 = 'DumpEncryptionKeyDigest'   # SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST
    0x00050028 = 'LSAISOConfig'              # SIPAEVENT_LSAISO_CONFIG

    # SIPAEVENTTYPE_AUTHORITY
    0x00060001 = 'NoAuthority'               # SIPAEVENT_NOAUTHORITY
    0x00060002 = 'AuthorityPubKey'           # SIPAEVENT_AUTHORITYPUBKEY

    # SIPAEVENTTYPE_LOADEDIMAGE
    0x00070001 = 'FilePath'                  # SIPAEVENT_FILEPATH
    0x00070002 = 'ImageSize'                 # SIPAEVENT_IMAGESIZE
    0x00070003 = 'HashAlgorithmID'           # SIPAEVENT_HASHALGORITHMID
    0x00070004 = 'AuthenticodeHash'          # SIPAEVENT_AUTHENTICODEHASH
    0x00070005 = 'AuthorityIssuer'           # SIPAEVENT_AUTHORITYISSUER
    0x00070006 = 'AuthoritySerial'           # SIPAEVENT_AUTHORITYSERIAL
    0x00070007 = 'ImageBase'                 # SIPAEVENT_IMAGEBASE
    0x00070008 = 'AuthorityPublisher'        # SIPAEVENT_AUTHORITYPUBLISHER
    0x00070009 = 'AuthoritySHA1Thumbprint'   # SIPAEVENT_AUTHORITYSHA1THUMBPRINT
    0x0007000A = 'ImageValidated'            # SIPAEVENT_IMAGEVALIDATED
    0x0007000B = 'ModuleSVN'                 # SIPAEVENT_MODULE_SVN

    # SIPAEVENTTYPE_TRUSTPOINT
    0x80080001 = 'Quote'                     # SIPAEVENT_QUOTE
    0x80080002 = 'QuoteSignature'            # SIPAEVENT_QUOTESIGNATURE
    0x80080003 = 'AIKID'                     # SIPAEVENT_AIKID
    0x80080004 = 'AIKPubDigest'              # SIPAEVENT_AIKPUBDIGEST

    # SIPAEVENTTYPE_ELAM
    0x00090001 = 'ELAMKeyname'               # SIPAEVENT_ELAM_KEYNAME
    0x00090002 = 'ELAMConfiguration'         # SIPAEVENT_ELAM_CONFIGURATION
    0x00090003 = 'ELAMPolicy'                # SIPAEVENT_ELAM_POLICY
    0x00090004 = 'ELAMMeasured'              # SIPAEVENT_ELAM_MEASURED

    # SIPAEVENTTYPE_VBS
    0x000A0001 = 'VBSVSMRequired'                # SIPAEVENT_VBS_VSM_REQUIRED
    0x000A0002 = 'VBSSecurebootRequired'         # SIPAEVENT_VBS_SECUREBOOT_REQUIRED
    0x000A0003 = 'VBSIOMMURequired'              # SIPAEVENT_VBS_IOMMU_REQUIRED
    0x000A0004 = 'VBSNXRequired'                 # SIPAEVENT_VBS_MMIO_NX_REQUIRED
    0x000A0005 = 'VBSMSRFilteringRequired'       # SIPAEVENT_VBS_MSR_FILTERING_REQUIRED
    0x000A0006 = 'VBSMandatoryEnforcement'       # SIPAEVENT_VBS_MANDATORY_ENFORCEMENT
    0x000A0007 = 'VBSHVCIPolicy'                 # SIPAEVENT_VBS_HVCI_POLICY
    0x000A0008 = 'VBSMicrosoftBootChainRequired' # SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED

    # SIPAEVENTTYPE_KSR
    0x000B0001 = 'KSRSignature'                  # SIPAEVENT_KSR_SIGNATURE
}

$Script:DigestAlgorithmMapping = @{
    [UInt16] 0  = 'TPM_ALG_ERROR'
    [UInt16] 1  = 'TPM_ALG_RSA'
    [UInt16] 4  = 'TPM_ALG_SHA1'
    [UInt16] 5  = 'TPM_ALG_HMAC'
    [UInt16] 6  = 'TPM_ALG_AES'
    [UInt16] 7  = 'TPM_ALG_MGF1'
    [UInt16] 8  = 'TPM_ALG_KEYEDHASH'
    [UInt16] 10 = 'TPM_ALG_XOR'
    [UInt16] 11 = 'TPM_ALG_SHA256'
    [UInt16] 12 = 'TPM_ALG_SHA384'
    [UInt16] 13 = 'TPM_ALG_SHA512'
    [UInt16] 16 = 'TPM_ALG_NULL'
    [UInt16] 18 = 'TPM_ALG_SM3_256'
}

$Script:HashAlgorithmMapping = @{
    0x00008001 = 'CALG_MD2'
    0x00008002 = 'CALG_MD4'
    0x00008003 = 'CALG_MD5'
    0x00008004 = 'CALG_SHA1'
    0x0000800C = 'CALG_SHA_256'
    0x0000800D = 'CALG_SHA_384'
    0x0000800E = 'CALG_SHA_512'
}

$Script:OSDeviceMapping = @{
    0x00000000 = 'UNKNOWN'
    0x00010001 = 'BLOCKIO_HARDDISK'
    0x00010002 = 'BLOCKIO_REMOVABLEDISK'
    0x00010003 = 'BLOCKIO_CDROM'
    0x00010004 = 'BLOCKIO_PARTITION'
    0x00010005 = 'BLOCKIO_FILE'
    0x00010006 = 'BLOCKIO_RAMDISK'
    0x00010007 = 'BLOCKIO_VIRTUALHARDDISK'
    0x00020000 = 'SERIAL'
    0x00030000 = 'UDP'
}

$Script:EventTypeMapping = @{
    [UInt32] 0  = 'EV_PREBOOT_CERT'          # The event field contains certificates such as the Validation Certificates.
    [UInt32] 1  = 'EV_POST_CODE'             # The digest field contains the SHA-1 hash of the POST portion of the BIOS. The event field SHOULD NOT contain the actual POST code but MAY contain informative information about the POST code.
    [UInt32] 2  = 'EV_UNUSED'                # The event type was never used and is considered reserved.
    [UInt32] 3  = 'EV_NO_ACTION'             # The event field contains informative data that was not extended into any PCR. The fields: pcrIndex and digest MUST contain the value 0.
    [UInt32] 4  = 'EV_SEPARATOR'             # Delimits actions taken during the Pre-Operating System State and the Operating System Present State
                                                # This will often be "WBCL" - Windows Boot Configuration Log (Microsoft's name for the TCG log)
    [UInt32] 5  = 'EV_ACTION'                # A specific action measured as a string defined in Section 10.4.3.
    [UInt32] 6  = 'EV_EVENT_TAG'             # The event field contains the structure defined in Section 10.4.2.1.
    [UInt32] 7  = 'EV_S_CRTM_CONTENTS'       # The digest field contains is the SHA-1 hash of the SCRTM. The event field SHOULD NOT contain the actual S-CRTM code but MAY contain informative information about the S-CRTM code.
    [UInt32] 8  = 'EV_S_CRTM_VERSION'        # The event field contains the version string of the SCRTM.
    [UInt32] 9  = 'EV_CPU_MICROCODE'         # The event field contains a descriptor of the microcode but the digest field contains the actual hash of the microcode patch that was applied.
    [UInt32] 10 = 'EV_PLATFORM_CONFIG_FLAGS' # The format and contents to be defined by the platform manufacturer. Examples of information contained in this event type are the capabilities of the platform?s measurements, whether the Owner has disabled measurements, etc.
    [UInt32] 11 = 'EV_TABLE_OF_DEVICES'      # The event field contains the Platform manufacturerprovided Table of Devices or other Platform manufacturer-defined information. The Platform manufacturer defines the content and format of the Table of Devices. The Host Platform Certificate may provide a reference to the meaning of these structures and data. This structure is measured into PCR[1] using the following.
    [UInt32] 12 = 'EV_COMPACT_HASH'          # This event is entered using the TCG_CompactHashLogExtendEvent. While it can be used by any function, it is typically used by IPL Code to measure events. The contents of the event field is specified by the caller but is not part of the measurement; rather, it is just informative.
    [UInt32] 13 = 'EV_IPL'                   # The digest field contains the SHA-1 hash of the IPL Code. The event field SHOULD NOT contain the actual IPL Code but MAY contain informative information about the IPL Code. Note: The digest may not cover the entire area hosting the IPL Image, but only the portion that contains the IPL Code. For example, if the IPL Image is a disk drive MBR, this MUST NOT include the portion of the MBR that contains the disk geometry.
    [UInt32] 14 = 'EV_IPL_PARTITION_DATA'    # The data and partition portion of the IPL Image.
    [UInt32] 15 = 'EV_NONHOST_CODE'          # The executable component of any Non-host Platform. The contents of the event field are defined by the manufacturer of the Non-host Platform.
    [UInt32] 16 = 'EV-NONHOST_CONFIG'        # The parameters associated with a Non-host Platform. The contents of the event field are defined by the manufacturer of the Non-host Platform.
    [UInt32] 17 = 'EV_NONHOST_INFO'          # The event is information about the presence of a Non-host Platform. This information could be, but is not required to be, information such as the Non-host Platform manufacturer, model, type, version, etc. The information and formatting is to be determined by the BIOS.
    [UInt32] (2147483648 + 1) = 'EV_EFI_VARIABLE_DRIVER_CONFIG'    # EFI variables, either defined in the EFI spec or private, that typically do not change from boot-to-boot and contain system configuration information.
    [UInt32] (2147483648 + 2) = 'EV_EFI_VARIABLE_BOOT'             # This event is used to measure boot variables. The event field MUST contain a UEFI_VARIABLE_DATA structure
    [UInt32] (2147483648 + 3) = 'EV_EFI_BOOT_SERVICES_APPLICATION' # EFI application (e.g. EFI OSLoader)
    [UInt32] (2147483648 + 4) = 'EV_EFI_BOOT_SERVICES_DRIVER'      # EFI Boot Services Drivers from adapter or loaded by driver in adapter.
    [UInt32] (2147483648 + 5) = 'EV_EFI_RUNTIME_SERVICES_DRIVER'   # EFI Runtime drivers from adapter or loaded by driver in adapter.
    [UInt32] (2147483648 + 6) = 'EV_EFI_GPT_EVENT'                 # GPT Table
    [UInt32] (2147483648 + 7) = 'EV_EFI_ACTION'                    # Measurement of a specific string value that indicates a specific event occurred during the platform or OS boot process.
    [UInt32] (2147483648 + 8) = 'EV_EFI_PLATFORM_FIRMWARE_BLOB'    # The event MUST contain a UEFI_PLATFORM_FIRMWARE_BLOB structure
    [UInt32] (2147483648 + 9) = 'EV_EFI_HANDOFF_TABLES'            # Describes the measurement of industry-standard tables and data structure regions.
    [UInt32] (2147483648 + 0x0A) = 'EV_EFI_HCRTM_EVENT'            # This event is used to record an event for the digest extended to PCR[0] as part of an H-CRTM event.
    [UInt32] (2147483648 + 0xE0) = 'EV_EFI_VARIABLE_AUTHORITY'     # Documented here: https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol
}

$Script:DigestSizeMapping = @{
    'TPM_ALG_SHA1'    = 20
    'TPM_ALG_SHA256'  = 32
    'TPM_ALG_SHA384'  = 48
    'TPM_ALG_SHA512'  = 64
    'TPM_ALG_SM3_256' = 32
}

# To-do: expand out the device subtype parsers
$Script:DevicePathTypeMapping = @{
    [Byte] 1    = 'HARDWARE_DEVICE_PATH' # Hardware Device Path
    [Byte] 2    = 'ACPI_DEVICE_PATH'     # ACPI Device Path
    [Byte] 3    = 'MESSAGING_DEVICE_PATH'# Messaging Device Path
    [Byte] 4    = 'MEDIA_DEVICE_PATH'    # Media Device Path
    [Byte] 5    = 'BBS_DEVICE_PATH'      # BIOS Boot Specification Device Path
    [Byte] 0x7F = 'END_DEVICE_PATH_TYPE'
}

$Script:MediaDeviceSubTypeMapping = @{
    [Byte] 1 = 'MEDIA_HARDDRIVE_DP'    # Corresponding struct: HARDDRIVE_DEVICE_PATH
    [Byte] 2 = 'MEDIA_CDROM_DP'        # Corresponding struct: CDROM_DEVICE_PATH
    [Byte] 3 = 'MEDIA_VENDOR_DP'       # Corresponding struct: ?
    [Byte] 4 = 'MEDIA_FILEPATH_DP'     # Corresponding struct: FILEPATH_DEVICE_PATH
    [Byte] 5 = 'MEDIA_PROTOCOL_DP'     # Corresponding struct: MEDIA_PROTOCOL_DEVICE_PATH
    [Byte] 6 = 'MEDIA_PIWG_FW_FILE_DP' # Corresponding struct: MEDIA_FW_VOL_FILEPATH_DEVICE_PATH
    [Byte] 7 = 'MEDIA_PIWG_FW_VOL_DP'  # Corresponding struct: MEDIA_FW_VOL_DEVICE_PATH
    [Byte] 8 = 'MEDIA_RELATIVE_OFFSET_RANGE_DP' # Corresponding struct: MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH
    [Byte] 9 = 'MEDIA_RAM_DISK_DP'     # Corresponding struct: MEDIA_RAM_DISK_DEVICE_PATH
}

$Script:ACPIDeviceSubTypeMapping = @{
    [Byte] 1 = 'ACPI_DP'               # Corresponding struct: ACPI_HID_DEVICE_PATH
    [Byte] 2 = 'ACPI_EXTENDED_DP'      # Corresponding struct: ACPI_EXTENDED_HID_DEVICE_PATH
    [Byte] 3 = 'ACPI_ADR_DP'           # Corresponding struct: ACPI_ADR_DEVICE_PATH
}

$Script:PartitionGUIDMapping = @{
    '00000000-0000-0000-0000-000000000000' = 'PARTITION_ENTRY_UNUSED_GUID'
    'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' = 'PARTITION_BASIC_DATA_GUID'
    'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' = 'PARTITION_SYSTEM_GUID'
    'e3c9e316-0b5c-4db8-817d-f92df00215ae' = 'PARTITION_MSFT_RESERVED_GUID'
    '5808c8aa-7e8f-42e0-85d2-e1e90434cfb3' = 'PARTITION_LDM_METADATA_GUID'
    'af9b60a0-1431-4f62-bc68-3311714a69ad' = 'PARTITION_LDM_DATA_GUID'
    'de94bba4-06d1-4d40-a16a-bfd50179d6ac' = 'PARTITION_MSFT_RECOVERY_GUID'
}
#endregion

# Helper function to retrieve SIPA events - i.e. Windows-specific PCR measurements
# I still have no clue what SIPA refers to. I use it because it's referenced all over wbcl.h.
# This function should not be exported.
function Get-SIPAEventData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Byte[]]
        $SIPAEventBytes
    )

    # We need to identify container structures and recurse accordingly.
    $ContainerType = 0x00010000

    $EventMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$SIPAEventBytes)
    $EventBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $EventMemoryStream, ([Text.Encoding]::Unicode)

    while (($EventBinaryReader.BaseStream.Position) -lt $SIPAEventBytes.Count) {
        $SIPAEventTypeVal = $EventBinaryReader.ReadInt32()
        $SIPAEventType = $SIPAEventMapping[$SIPAEventTypeVal]

        $SIPAEventSize = $EventBinaryReader.ReadUInt32()
        $EventBytes = $EventBinaryReader.ReadBytes($SIPAEventSize)

        # All SIPA event types _should_ be defined but just in case one isn't, print it out in hex.
        if (-not $SIPAEventType) { $SIPAEventType = "0x$($SIPAEventTypeVal.ToString('X8'))" }

        if ((($SIPAEventTypeVal -band 0x000F0000) -eq $ContainerType) -or (($SIPAEventType -eq 'NoAuthority') -or ($SIPAEventType -eq 'AuthorityPubKey'))) {
            switch ($SIPAEventType) {
                'TrustBoundary' {
                    $PropertyTemplate = [Ordered] @{
                        Information = $null
                        PreOSParameters = $null
                        OSParameters = $null
                        LoadedModules = $null # This appears to be the only one that will have multiple entries
                        ELAM = $null
                        VBS = $null
                    }

                    $InformationTemplate = @{
                        Information = $null
                        BootCounter = $null
                        TransferControl = $null
                        ApplicationReturn = $null
                        BitlockerUnlock = $null
                        EventCounter = $null
                        CounterID = $null
                        MORBitNotCancelable = $null
                        ApplicationSVN = $null
                        SVNChainStatus = $null
                        MORBitAPIStatus = $null
                    }

                    $PreOSTemplate = @{
                        BootDebugging = $null
                        BootRevocationList = $null
                    }

                    $OSTemplate = @{
                        OSKernelDebug = $null
                        CodeIntegrity = $null
                        TestSigning = $null
                        DataExecutionPrevention = $null
                        SafeMode = $null
                        WinPE = $null
                        PhysicalAddressExtension = $null
                        OSDevice = $null
                        SystemRoot = $null
                        HypervisorLaunchType = $null
                        HypervisorPath = $null
                        HypervisorIOMMUPolicy = $null
                        HypervisorDebug = $null
                        DriverLoadPolicy = $null
                        SIPolicy = $null
                        HypervisorMMIONXPolicy = $null
                        HypervisorMSRFilterPolicy = $null
                        VSMLaunchType = $null
                        OSRevocationList = $null
                        VSMIDKInfo = $null
                        FlightSigning = $null
                        PagefileEncryptionEnabled = $null
                        VSMIDKSInfo = $null
                        HibernationDisabled = $null
                        DumpsDisabled = $null
                        DumpEncryptionEnabled = $null
                        DumpEncryptionKeyDigest = $null
                        LSAISOConfig = $null
                    }

                    $VBSTemplate = @{
                        VBSVSMRequired = $null
                        VBSSecurebootRequired = $null
                        VBSIOMMURequired = $null
                        VBSNXRequired = $null
                        VBSMSRFilteringRequired = $null
                        VBSMandatoryEnforcement = $null
                        VBSHVCIPolicy = $null
                        VBSMicrosoftBootChainRequired = $null
                    }

                    $ContainerEvents = Get-SIPAEventData -SIPAEventBytes $EventBytes

                    $LoadedModuleList = New-Object 'System.Collections.Generic.List[PSObject]'
                    $ELAMList = New-Object 'System.Collections.Generic.List[PSObject]'

                    $InformationTemplateSet = $False
                    $PreOSTemplateSet = $False
                    $OSTemplateSet = $False
                    $VBSTemplateSet = $False

                    foreach ($Container in $ContainerEvents) {
                        if ($Container.SIPAEventType -eq 'LoadedModuleAggregation') {
                            $LoadedModuleList.Add($Container.SIPAEventData)
                        } elseif ($Container.SIPAEventType -eq 'ELAMAggregation') {
                            $ELAMList.Add($Container.SIPAEventData)
                        } else {
                            switch ($Container.Category) {
                                'Information' {
                                    $InformationTemplateSet = $True
                                    $InformationTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                                }

                                'PreOSParameter' {
                                    $PreOSTemplateSet = $True
                                    $PreOSTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                                }

                                'OSParameter' {
                                    $OSTemplateSet = $True
                                    $OSTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                                }

                                'VBS' {
                                    $VBSTemplateSet = $True
                                    $VBSTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                                }
                            }
                        }
                    }

                    $InformationObject = $null
                    $PreOSParameterObject = $null
                    $OSParameterObject = $null
                    $VBSObject = $null

                    if ($InformationTemplateSet) { $InformationObject = [PSCustomObject] $InformationTemplate }
                    if ($PreOSTemplateSet) { $PreOSParameterObject = [PSCustomObject] $PreOSTemplate }
                    if ($OSTemplateSet) { $OSParameterObject = [PSCustomObject] $OSTemplate }
                    if ($VBSTemplateSet) { $VBSObject = [PSCustomObject] $VBSTemplate }

                    $PropertyTemplate['Information'] = $InformationObject
                    $PropertyTemplate['PreOSParameters'] = $PreOSParameterObject
                    $PropertyTemplate['OSParameters'] = $OSParameterObject
                    $PropertyTemplate['VBS'] = $VBSObject
                    if ($LoadedModuleList.Count) { $PropertyTemplate['LoadedModules'] = $LoadedModuleList }
                    if ($ELAMList) { $PropertyTemplate['ELAM'] = $ELAMList }

                    [PSCustomObject] $PropertyTemplate
                }

                'LoadedModuleAggregation' {
                    $PropertyTemplate = [Ordered] @{
                        FilePath = $null
                        ImageBase = $null
                        ImageSize = $null
                        HashAlgorithmID = $null
                        AuthenticodeHash = $null
                        ImageValidated = $null
                        AuthorityIssuer = $null
                        AuthorityPublisher = $null
                        AuthoritySerial = $null
                        AuthoritySHA1Thumbprint = $null
                        ModuleSVN = $null
                    }

                    $ContainerEvents = Get-SIPAEventData -SIPAEventBytes $EventBytes

                    foreach ($Container in $ContainerEvents) {
                        $PropertyTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                    }

                    $ContainerObject = [PSCustomObject] $PropertyTemplate

                    [PSCustomObject] @{
                        IsContainer = $False
                        SIPAEventType = $SIPAEventType
                        SIPAEventData = $ContainerObject
                    }
                }

                'ELAMAggregation' {
                    $PropertyTemplate = [Ordered] @{
                        ELAMKeyname = $null
                        ELAMConfiguration = $null
                        ELAMPolicy = $null
                        ELAMMeasured = $null
                    }

                    $ContainerEvents = Get-SIPAEventData -SIPAEventBytes $EventBytes

                    foreach ($Container in $ContainerEvents) {
                        $PropertyTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                    }

                    $ContainerObject = [PSCustomObject] $PropertyTemplate

                    [PSCustomObject] @{
                        IsContainer = $False
                        SIPAEventType = $SIPAEventType
                        SIPAEventData = $ContainerObject
                    }
                }

                'TrustpointAggregation' {
                    $PropertyTemplate = [Ordered] @{
                        AIKID = $null
                        AIKPubDigest = $null
                        Quote = $null
                        QuoteSignature = $null
                    }

                    $ContainerEvents = Get-SIPAEventData -SIPAEventBytes $EventBytes

                    foreach ($Container in $ContainerEvents) {
                        $PropertyTemplate[$Container.SIPAEventType] = $Container.SIPAEventData
                    }

                    $ContainerObject = [PSCustomObject] $PropertyTemplate

                    $ContainerObject
                }

                'NoAuthority' {
                    [PSCustomObject] @{
                        NoAuthority = $EventBytes
                    }
                }

                'AuthorityPubKey' {
                    [PSCustomObject] @{
                        AuthorityPubKey = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'
                    }
                }

                default {
                    # Return raw event data for KSR containers until I have data to actually parse
                    # KSRAggregation
                    # KSRSignedMeasurementAggregation

                    Write-Warning "Uncategorized SIPA Event Category"

                    [PSCustomObject] @{
                        IsContainer = $True
                        SIPAEventType = $SIPAEventType
                        SIPAEventData = Get-SIPAEventData -SIPAEventBytes $EventBytes
                    }
                }
            }
        } else {
            # Each SIPA event data structure will differ depending on the type.
            # Many of these data types are not formally defined but can be easily inferred.
            # If the strucutre is not explicitly stated, it is inferred from multiple events.
            switch ($SIPAEventType) {
                'Information'         { $EventData = $EventBytes; $Category = 'Information' }
                'BootCounter'         { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'TransferControl'     { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'ApplicationReturn'   { $EventData = $EventBytes; $Category = 'Information' }
                'BitlockerUnlock'     { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'EventCounter'        { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'CounterID'           { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'MORBitNotCancelable' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'ApplicationSVN'      { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'SVNChainStatus'      { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                # MemoryOverwriteRequest - Introduced in the TCG Platform Reset Attack Mitigation Specification
                'MORBitAPIStatus'     { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'BootDebugging'       { $EventData = [Bool] $EventBytes[0]; $Category = 'PreOSParameter' }

                'BootRevocationList' {
                    # SIPAEVENT_REVOCATION_LIST_PAYLOAD structure

                    # I haven't spent time to determine how to translate the creation time yet.
                    $CreationTime = [BitConverter]::ToUInt64($EventBytes, 0)
                    $DigestLength = [BitConverter]::ToUInt32($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0C)]
                    $Digest = [BitConverter]::ToString($EventBytes[0x0E..(0x0E + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'PreOSParameter'

                    $EventData = [PSCustomObject] @{
                        CreationTime = $CreationTime
                        HashAlgorithm = $HashAlgorithm
                        Digest = $Digest
                    }
                }

                'OSKernelDebug'            { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'CodeIntegrity'            { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'TestSigning'              { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DataExecutionPrevention'  { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'SafeMode'                 { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'WinPE'                    { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'PhysicalAddressExtension' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'OSDevice'                 { $EventData = $OSDeviceMapping[[BitConverter]::ToInt32($EventBytes, 0)]; $Category = 'OSParameter' }
                'SystemRoot'               { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'OSParameter' }
                'HypervisorLaunchType'     { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorPath'           { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'OSParameter' }
                'HypervisorIOMMUPolicy'    { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorDebug'          { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DriverLoadPolicy'         { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'OSParameter' }

                'SIPolicy' {
                    # SIPAEVENT_SI_POLICY_PAYLOAD structure

                    $Revision = [Int32][BitConverter]::ToInt16($EventBytes, 0)
                    $Build = [Int32][BitConverter]::ToInt16($EventBytes, 2)
                    $Minor = [Int32][BitConverter]::ToInt16($EventBytes, 4)
                    $Major = [Int32][BitConverter]::ToInt16($EventBytes, 6)
                    $PolicyVersion = New-Object -TypeName Version -ArgumentList @($Major, $Minor, $Build, $Revision)

                    $PolicyNameLength = [BitConverter]::ToInt16($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0A)]

                    $DigestLength = [BitConverter]::ToUInt16($EventBytes, 0x0C)
                    $DigestIndex = 0x10 + $PolicyNameLength

                    $PolicyName = [Text.Encoding]::Unicode.GetString($EventBytes[0x10..($DigestIndex - 1)]).TrimEnd(@(0))
                    $Digest = [BitConverter]::ToString($EventBytes[($DigestIndex)..($DigestIndex + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        PolicyVersion = $PolicyVersion
                        PolicyName = $PolicyName
                        HashAlgorithm = $HashAlgorithm
                        Digest = $Digest
                    }
                }

                'HypervisorMMIONXPolicy'    { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorMSRFilterPolicy' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'VSMLaunchType'             { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }

                'OSRevocationList' {
                    # SIPAEVENT_REVOCATION_LIST_PAYLOAD structure

                    # I haven't spent time to determine how to translate the creation time yet.
                    $CreationTime = [BitConverter]::ToUInt64($EventBytes, 0)
                    $DigestLength = [BitConverter]::ToUInt32($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0C)]
                    $Digest = [BitConverter]::ToString($EventBytes[0x0E..(0x0E + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        CreationTime = $CreationTime
                        HashAlgorithm = $HashAlgorithm
                        Digest = $Digest
                    }
                }

                'VSMIDKInfo' {
                    # SIPAEVENT_VSM_IDK_INFO_PAYLOAD structure

                    # Type: VSM_IDK_ALG_ID (I can't find this defined anywhere. I'm personally not worried about it. IDK what "IDK" is)
                    # This should only be 1.
                    $KeyAlgID = [BitConverter]::ToUInt32($EventBytes, 0)
                    $null = [BitConverter]::ToUInt32($EventBytes, 4) # KeyBitLength
                    $PublicExpLengthBytes = [BitConverter]::ToUInt32($EventBytes, 8)
                    $ModulusSizeBytes = [BitConverter]::ToUInt32($EventBytes, 0x0C)

                    $ModulusIndex = 0x10 + $PublicExpLengthBytes

                    [Byte[]] $PublicExponent = $EventBytes[0x10..($ModulusIndex - 1)]
                    [Byte[]] $Modulus = $EventBytes[($ModulusIndex)..($ModulusIndex + $ModulusSizeBytes - 1)]

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        KeyAlgID = $KeyAlgID
                        PublicExponent = ($PublicExponent | ForEach-Object {$_.ToString('X2')}) -join ':'
                        Modulus = ($Modulus | ForEach-Object {$_.ToString('X2')}) -join ':'
                    }
                }

                'FlightSigning'             { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'PagefileEncryptionEnabled' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }

                'VSMIDKSInfo' {
                    # SIPAEVENT_VSM_IDK_INFO_PAYLOAD structure

                    # Type: VSM_IDK_ALG_ID (I can't find this defined anywhere. I'm personally not worried about it. IDK what "IDK" is)
                    # This should only be 1.
                    $KeyAlgID = [BitConverter]::ToUInt32($EventBytes, 0)
                    $null = [BitConverter]::ToUInt32($EventBytes, 4) # KeyBitLength
                    $PublicExpLengthBytes = [BitConverter]::ToUInt32($EventBytes, 8)
                    $ModulusSizeBytes = [BitConverter]::ToUInt32($EventBytes, 0x0C)

                    $ModulusIndex = 0x10 + $PublicExpLengthBytes

                    [Byte[]] $PublicExponent = $EventBytes[0x10..($ModulusIndex - 1)]
                    [Byte[]] $Modulus = $EventBytes[($ModulusIndex)..($ModulusIndex + $ModulusSizeBytes - 1)]

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        KeyAlgID = $KeyAlgID
                        PublicExponent = ($PublicExponent | ForEach-Object {$_.ToString('X2')}) -join ':'
                        Modulus = ($Modulus | ForEach-Object {$_.ToString('X2')}) -join ':'
                    }
                }

                'HibernationDisabled'           { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DumpsDisabled'                 { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DumpEncryptionEnabled'         { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                # SHA-256 digest of thefollowing regkey value:
                # CurrentControlSet\Control\CrashControl\EncryptionCertificates\Certificate.1::PublicKey
                'DumpEncryptionKeyDigest'       { $EventData = $EventBytes; $Category = 'OSParameter' }
                'LSAISOConfig'                  { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'OSParameter' }
                'FilePath'                      { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'SIPAEventData'                 { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'HashAlgorithmID'               { $EventData = $HashAlgorithmMapping[[BitConverter]::ToInt32($EventBytes, 0)]; $Category = 'LoadedImage' }
                'AuthenticodeHash'              { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'AuthorityIssuer'               { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'AuthoritySerial'               { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'ImageBase'                     { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'ImageSize'                     { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'AuthorityPublisher'            { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'AuthoritySHA1Thumbprint'       { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'ImageValidated'                { $EventData = [Bool] $EventBytes[0]; $Category = 'LoadedImage' }
                'ModuleSVN'                     { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'LoadedImage' }
                'AIKID'                         { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'Trustpoint' }
                'AIKPubDigest'                  { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'Trustpoint' }
                'Quote'                         { $EventData = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'; $Category = 'Trustpoint' }
                'QuoteSignature'                { $EventData = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'; $Category = 'Trustpoint' }
                'VBSVSMRequired'                { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSSecurebootRequired'         { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSIOMMURequired'              { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSNXRequired'                 { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSMSRFilteringRequired'       { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSMandatoryEnforcement'       { $EventData = $EventBytes; $Category = 'VBS' }
                'VBSHVCIPolicy'                 { $EventData = $EventBytes; $Category = 'VBS' }
                'VBSMicrosoftBootChainRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'ELAMKeyname'                   { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'ELAM' }
                'ELAMMeasured'                  { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'ELAM' }
                'ELAMConfiguration'             { $EventData = $EventBytes; $Category = 'ELAM' }
                'ELAMPolicy'                    { $EventData = $EventBytes; $Category = 'ELAM' }

                default {
                    $Category = 'Uncategorized'
                    $EventData = $EventBytes
                }
            }

            [PSCustomObject] @{
                Category = $Category
                SIPAEventType = $SIPAEventType
                SIPAEventData = $EventData
            }
        }
    }

    $EventBinaryReader.Close()
}

function Get-TPMDeviceInfo {
<#
.SYNOPSIS

Retrieves TPM information.

.DESCRIPTION

Get-TPMDeviceInfo retrieves limited TPM information.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.EXAMPLE

Get-TPMDeviceInfo
#>

    $TPM_DEVICE_INFO_Size = 16

    $DeviceInfo = New-Object -TypeName TPMBaseServices.TPM_DEVICE_INFO
    $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_GetDeviceInfo($TPM_DEVICE_INFO_Size, [Ref] $DeviceInfo)

    if ($Result -eq 0) {
        $DeviceInfo
    } else {
        Write-Error "Tbsi_GetDeviceInfo: $($TBSReturnCodes[$Result])"
    }
}

function Get-TCGLogContent {
<#
.SYNOPSIS

Retrieves the contents of the Trusted Computing Group (TCG) log.

.DESCRIPTION

Get-TCGLogContent retrieves the contents of the TCG log (referred to as the "Windows Boot Configuration Log" (WBCL) by Microsoft). This log captures the various boot and runtime measurements used for device health attestation.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER LogType

Specifies the type of TCG log to retrieve. The following arguments are supported:

* SRTMCurrent (default): The log associated with PCRs 0-15 for the current session (boot or resume).
  * This option retrieves the contents of HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL
* DRTMCurrent: The log associated with PCRs 17-22 for the current session (boot or resume).
  * This option retrieves the contents of HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCLDrtm
  * The presence of DRTM is validated with NtQuerySystemInformation - SYSTEM_BOOT_ENVIRONMENT_INFORMATION.DbgMeasuredLaunch
* SRTMBoot: The log associated with PCRs 0-15 for the most recent clean boot session.
  * This log is retrieved from the most current MeasuredBoot log from a clean boot state. For example, if the most recent log is C:\Windows\Logs\MeasuredBoot\0000000029-0000000003.log, This option will retrieve C:\Windows\Logs\MeasuredBoot\0000000029-0000000000.log (indicating the first MeasuredBoot log taken from a clean boot state).
* SRTMResume: The log associated with PCRs 0-15 for the most recent resume from hibernation.
  * This log is retrieved from the most current MeasuredBoot log taken immediately after the clean state boot log. For example, if the clean boot log is C:\Windows\Logs\MeasuredBoot\0000000029-0000000000.log, this options will retrieve C:\Windows\Logs\MeasuredBoot\0000000029-0000000001.log.

.EXAMPLE

Get-TCGLogContent

Retrieves the TCG log bytes associated with PCRs 0-15 for the current session (boot or resume).

.EXAMPLE

Get-TCGLogContent -LogType SRTMBoot

Retrieves the TCG log bytes associated with PCRs 0-15 for the most recent clean boot session.

.OUTPUTS

System.Byte[]

Outputs a byte array consisting of a raw TCG log. Supply the byte array to ConvertTo-TCGEventLog to parse the contents of the log.
#>

    [OutputType([Byte[]])]
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [String]
        [ValidateSet('SRTMCurrent', 'DRTMCurrent', 'SRTMBoot', 'SRTMResume')]
        $LogType = 'SRTMCurrent'
    )

    switch ($LogType) {
        'SRTMCurrent' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_CURRENT }
        'DRTMCurrent' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_DRTM_CURRENT }
        'SRTMBoot'    { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_BOOT }
        'SRTMResume'  { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_RESUME }
    }

    $TCGLogSize = 0

    # Supply an empty buffer so that the size of the buffer will be returned.
    $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_Get_TCG_Log_Ex($LogTypeEnumVal, [IntPtr]::Zero, [Ref] $TCGLogSize)

    if ($Result -ne 0) {
        Write-Error "Tbsi_Get_TCG_Log_Ex: $($TBSReturnCodes[$Result])"

        return
    }

    if ($TCGLogSize) {
        Write-Verbose "TCG log size: 0x$($TCGLogSize.ToString('X8'))"
        $TCGLogBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TCGLogSize)

        # Initialize the buffer to zero. AllocHGlobal won't initialize memory nor will Tbsi_Get_TCG_Log_Ex.
        for ($i = 0; $i -lt $TCGLogSize; $i++) {
            [Runtime.InteropServices.Marshal]::WriteByte($TCGLogBuffer, $i, 0)
        }

        $TCGLogBytes = New-Object -TypeName Byte[]($TCGLogSize)

        # Read the TCG log buffer.
        $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_Get_TCG_Log_Ex($LogTypeEnumVal, $TCGLogBuffer, [Ref] $TCGLogSize)

        if ($Result -ne 0) {
            Write-Error "Tbsi_Get_TCG_Log_Ex: $($TBSReturnCodes[$Result])"

            # Free the unmanaged memory
            [Runtime.InteropServices.Marshal]::FreeHGlobal($TCGLogBuffer)

            return
        }

        # Copy the buffer to the byte array
        [Runtime.InteropServices.Marshal]::Copy($TCGLogBuffer, $TCGLogBytes, 0, $TCGLogSize)

        # Free the unmanaged memory
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TCGLogBuffer)
    }

    $TCGLogBytes
}

filter ConvertTo-TCGEventLog {
<#
.SYNOPSIS

Parses a Trusted Computing Group (TCG) log.

.DESCRIPTION

ConvertTo-TCGEventLog parses one or more TCG logs (referred to as the "Windows Boot Configuration Log" (WBCL) by Microsoft). This log captures the various boot and runtime measurements used for device health attestation. ConvertTo-TCGEventLog will parse the log as a byte array or from one or more log files on disk.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER LogBytes

Specifies an array of bytes consisting of a raw TCG log.

.PARAMETER LogPath

Specifies the path to one or more TCG log files. On Windows 10 with TPM enabled, these logs are located at %windir%\Logs\MeasuredBoot by default. Optionally, you can specify an alternate TCG log path with HKLM\System\CurrentControlSet\services\TPM\WBCLPath (REG_EXPAND_SZ).

.PARAMETER

Specifies that any object that return a signature object should return an X509Certificate object. If this switch is not specified, X509Certificate2 objects will be returned. This switch is present in order to reduce the amount of data in JSON output.

.EXAMPLE

$TCGLogBytes = Get-TCGLogContent -LogType SRTMCurrent
$TCGLog = ConvertTo-TCGEventLog -LogBytes $TCGLogBytes

.EXAMPLE

ls C:\Windows\Logs\MeasuredBoot\*.log | ConvertTo-TCGEventLog

.EXAMPLE

ConvertTo-TCGEventLog -LogPath C:\Windows\Logs\MeasuredBoot\0000000001-0000000000.log

.EXAMPLE

ConvertTo-TCGEventLog -LogBytes (Get-TCGLogContent -LogType SRTMBoot) -MinimizedX509CertInfo | ConvertTo-Json -Depth 8 | Out-File TCGlog.json

Using the -MinimizedX509CertInfo so that JSON output is not as verbose.

.INPUTS

System.String

Accepts one or more TCG log file paths.

.OUTPUTS

PSCustomObject

Outputs a parsed TCG log.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [Byte[]]
        $LogBytes,

        [Parameter(Mandatory, ParameterSetName = 'LogFile', ValueFromPipelineByPropertyName)]
        [String]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        $LogPath,

        [Switch]
        $MinimizedX509CertInfo
    )

    $LogFullPath = $null
    # The header should be at least this long in order to proceed with parsing.
    $MinimumHeaderLength = 65

    if ($LogBytes) {
        $TCGLogBytes = $LogBytes

        if ($TCGLogBytes.Count -lt $MinimumHeaderLength) {
            Write-Error "The supplied byte array is not of sufficient size to be a TCG log. It must be at least $MinimumHeaderLength bytes in length. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
            return
        }
    } else {
        # -LogPath was specified
        $LogFullPath = (Resolve-Path $LogPath).Path
        $TCGLogBytes = [IO.File]::ReadAllBytes($LogFullPath)

        if ($TCGLogBytes.Count -lt $MinimumHeaderLength) {
            Write-Error "$LogFullPath is not of sufficient size to be a TCG log. It must be at least $MinimumHeaderLength bytes in length. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
            return
        }
    }

    if ($MinimizedX509CertInfo) {
        $SignatureObjectType = 'Security.Cryptography.X509Certificates.X509Certificate'
    } else {
        $SignatureObjectType = 'Security.Cryptography.X509Certificates.X509Certificate2'
    }

    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$TCGLogBytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    } catch {
        throw $_
        return
    }

    $PCRIndex = $BinaryReader.ReadUInt32()

    if ($PCRIndex -ne 0) {
        Write-Error "TCG_PCR_EVENT.PCRIndex expected value: 0. Actual value: $PCRIndex. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $EventType = $EventTypeMapping[$BinaryReader.ReadUInt32()]

    if ($EventType -ne 'EV_NO_ACTION') {
        Write-Error "TCG_PCR_EVENT.EventType expected value: EV_NO_ACTION. Actual value: $EventType. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $Digest = $BinaryReader.ReadBytes(20)
    $DigestString = [BitConverter]::ToString($Digest).Replace('-', '')

    if ($DigestString -ne '0000000000000000000000000000000000000000') {
        Write-Error "TCG_PCR_EVENT.Digest expected value: 0000000000000000000000000000000000000000. Actual value: $DigestString. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $EventSize = $BinaryReader.ReadUInt32()

    # Read the TCG_EfiSpecIdEventStruct instance contents
    $Signature = [Text.Encoding]::ASCII.GetString($BinaryReader.ReadBytes(16)).TrimEnd(@(0, 0))

    if ($Signature -ne 'Spec ID Event03') {
        Write-Error "TCG_PCR_EVENT.Event.Signature expected value: Spec ID Event03. Actual value: $Signature. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    # At this point, there is a very reasonable confidence that this is a well-formed TCG log.

    $PlatformClass = $BinaryReader.ReadUInt32()
    $SpecVersionMinor = $BinaryReader.ReadByte()
    $SpecVersionMajor = $BinaryReader.ReadByte()
    $SpecErrata = $BinaryReader.ReadByte()
    $UintNSize = $BinaryReader.ReadByte()
    $NumberOfAlgorithms = $BinaryReader.ReadUInt32()

    $DigestSizes = New-Object -TypeName PSObject[]($NumberOfAlgorithms)

    for ($i = 0; $i -lt $NumberOfAlgorithms; $i++) {
        $DigestSizes[$i] = New-Object -TypeName PSObject -Property @{
            HashAlg = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
            DigestSize = $BinaryReader.ReadUInt16()
        }
    }

    $VendorInfoSize = $BinaryReader.ReadByte()
    $VendorInfo = $BinaryReader.ReadBytes($vendorInfoSize)

    # Described here: https://msdn.microsoft.com/en-us/library/windows/desktop/bb530712(v=vs.85).aspx
    $TCG_EfiSpecIdEventStruct = [PSCustomObject] @{
        PSTypeName = 'TCGEfiSpecIdEvent'
        Signature = $Signature
        PlatformClass = $PlatformClass
        SpecVersionMinor = $SpecVersionMinor
        SpecVersionMajor = $SpecVersionMajor
        SpecErrata = $SpecErrata
        UintNSize = $UintNSize
        NumberOfAlgorithms = $NumberOfAlgorithms
        DigestSizes = $DigestSizes
        VendorInfoSize = $VendorInfoSize
        VendorInfo = $VendorInfo
    }

    $TCGHeader = [PSCustomObject] @{
        PSTypeName = 'TCGPCREvent'
        PCR = $PCRIndex
        EventType = $EventType
        Digest = $DigestString
        Event = $TCG_EfiSpecIdEventStruct
    }

    # Loop through all the remaining measurements, parsing each TCG_PCR_EVENT2 struct along the way
    $Events = while ($BinaryReader.PeekChar() -ne -1) {
        $PCRIndex = $BinaryReader.ReadInt32()

        $EventTypeVal = $BinaryReader.ReadUInt32()
        $EventType = $EventTypeMapping[$EventTypeVal]
        if (-not $EventType) { $EventType = $EventTypeVal.ToString('X8') }

        # Multiple digests can be calculated/stored but in plractice, you will likely only over see one digest.
        $DigestValuesCount = $BinaryReader.ReadUInt32()

        if ($DigestValuesCount -eq 1) {
            $HashAlg = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
            $DigestSize = $DigestSizeMapping[$HashAlg]

            $Digests = [BitConverter]::ToString($BinaryReader.ReadBytes($DigestSize)).Replace('-', '')
        } else {
            $Digests = New-Object -TypeName PSObject[]($DigestValuesCount)

            for ($i = 0; $i -lt $DigestValuesCount; $i++) {
                $HashAlg = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
                $DigestSize = $DigestSizeMapping[$HashAlg]

                $Digests[$i] = [BitConverter]::ToString($BinaryReader.ReadBytes($DigestSize)).Replace('-', '')
            }
        }
        

        $EventSize = $BinaryReader.ReadUInt32()

        $Event = $null

        # Parse specific event types. Event types that are not explicitly parsed will return a byte array of the contents.
        switch ($EventType) {
            'EV_S_CRTM_CONTENTS' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $Event = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_POST_CODE' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $Event = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_EFI_PLATFORM_FIRMWARE_BLOB' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $BlobBase = [BitConverter]::ToUInt64($EventBytes, 0)
                $BlobLength = [BitConverter]::ToUInt64($EventBytes, 8)

                # Chipsec can dump this for validation:
                # chipsec_util.py mem read [BlobBase] [BlobLength] firmwareblob.bin
                # What's dumped will likely be a firmware volume. I use UEFITool.exe to extract contents.

                $Event = [PSCustomObject] @{
                    PSTypeName = 'TCGUEFIPlatformFirmwareBlob'
                    BlobBase = $BlobBase
                    BlobLength = $BlobLength
                }
            }

            'EV_EVENT_TAG' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                # These will be Windows-specific data structures
                $Event = Get-SIPAEventData -SIPAEventBytes $EventBytes
            }

            'EV_NO_ACTION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                if ($PCRIndex -eq -1) {
                    # Extact TrustPoint information - used for log attestation
                    $Event = Get-SIPAEventData -SIPAEventBytes $EventBytes
                } else {
                    $Event = $EventBytes
                }
            }

            'EV_EFI_GPT_EVENT' {
                # This will consist of a UEFI_GPT_DATA structure.

                # EFI_TABLE_HEADER: Start
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $GPTMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$EventBytes)
                $GPTBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $GPTMemoryStream, ([Text.Encoding]::Unicode)

                $Signature = [Text.Encoding]::ASCII.GetString($GPTBinaryReader.ReadBytes(8)).TrimEnd(@(0))
                $SpecMinor = [Int32] $GPTBinaryReader.ReadInt16()
                $SpecMajor = [Int32] $GPTBinaryReader.ReadInt16()

                $Revision = New-Object -TypeName Version -ArgumentList @($SpecMajor, $SpecMinor, 0, 0)

                $null = $GPTBinaryReader.ReadUInt32() # HeaderSize
                $CRC32 = $GPTBinaryReader.ReadUInt32()
                $null = $GPTBinaryReader.ReadUInt32() # Reserved

                $TableHeader = [PSCustomObject] @{
                    Signature = $Signature
                    Revision = $Revision
                    CRC32 = $CRC32
                }
                # EFI_TABLE_HEADER: End

                # EFI_PARTITION_TABLE_HEADER: Start
                $MyLBA = $GPTBinaryReader.ReadUInt64()
                $AlternateLBA = $GPTBinaryReader.ReadUInt64()
                $FirstUsableLBA = $GPTBinaryReader.ReadUInt64()
                $LastUsableLBA = $GPTBinaryReader.ReadUInt64()

                $DiskGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)

                $PartitionEntryLBA = $GPTBinaryReader.ReadUInt64()
                $NumberOfPartitionEntries = $GPTBinaryReader.ReadUInt32()
                $SizeOfPartitionEntry = $GPTBinaryReader.ReadUInt32()
                $PartitionEntryArrayCRC32 = $GPTBinaryReader.ReadUInt32()
                # EFI_PARTITION_TABLE_HEADER: End

                $EFIPartitionHeader = [PSCustomObject] @{
                    Header = $TableHeader
                    MyLBA = $MyLBA
                    AlternateLBA = $AlternateLBA
                    FirstUsableLBA = $FirstUsableLBA
                    LastUsableLBA = $LastUsableLBA
                    DiskGUID = $DiskGUID
                    PartitionEntryLBA = $PartitionEntryLBA
                    NumberOfPartitionEntries = $NumberOfPartitionEntries
                    SizeOfPartitionEntry = $SizeOfPartitionEntry
                    PartitionEntryArrayCRC32 = $PartitionEntryArrayCRC32
                }

                $NumberOfPartitions = $GPTBinaryReader.ReadUInt64()

                $Partitions = New-Object PSObject[]($NumberOfPartitions)

                for ($i = 0; $i -lt $NumberOfPartitions; $i++) {
                    $PartitionTypeGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)
                    $PartitionTypeName = $PartitionGUIDMapping[$PartitionTypeGUID.Guid]
                    $UniquePartitionGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)
                    $StartingLBA = $GPTBinaryReader.ReadUInt64()
                    $EndingLBA = $GPTBinaryReader.ReadUInt64()
                    $Attributes = $GPTBinaryReader.ReadUInt64()
                    $PartitionName = [Text.Encoding]::Unicode.GetString($GPTBinaryReader.ReadBytes(72)).TrimEnd(@(0))

                    $Partitions[$i] = [PSCustomObject] @{
                        PartitionTypeGUID = $PartitionTypeGUID
                        PartitionTypeName = $PartitionTypeName
                        UniquePartitionGUID = $UniquePartitionGUID
                        StartingLBA = $StartingLBA
                        EndingLBA = $EndingLBA
                        Attributes = $Attributes
                        PartitionName = $PartitionName
                    }
                }

                $Event = [PSCustomObject] @{
                    EfiPartitionHeader = $EfiPartitionHeader
                    NumberOfPartitions = $NumberOfPartitions
                    Partitions = $Partitions
                }

                $GPTBinaryReader.Close()
            }

            'EV_SEPARATOR' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                if ($PCRIndex -gt 11) {
                    $Event = [Text.Encoding]::ASCII.GetString($EventBytes)
                } else {
                    $Event = ($EventBytes | ForEach-Object {$_.ToString('X2')}) -join ':'
                }
            }

            'EV_EFI_VARIABLE_AUTHORITY' {
                $VariableName = [Guid] $BinaryReader.ReadBytes(16)
                $UnicodeNameLength = $BinaryReader.ReadUInt64()
                $VariableDataLength = $BinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($BinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                [Byte[]] $SignatureDataBytes = $BinaryReader.ReadBytes($VariableDataLength)

                if (@('PK', 'KEK', 'db', 'dbx') -contains $UnicodeName) {
                    # A EFI_SIGNATURE_DATA instance
                    # "The EFI_VARIABLE_DATA.VariableData value shall be the EFI_SIGNATURE_DATA value from
                    # the EFI_SIGNATURE_LIST that contained the authority that was used to validate the image
                    # and the EFI_VARIABLE_DATA.VariableName shall be set to EFI_IMAGE_SECURITY_DATABASE_GUID.
                    # The EFI_VARIABLE_DATA.UnicodeName shall be set to the value of EFI_IMAGE_SECURITY_DATABASE."
                    $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]
                    $SignatureBytes = $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]

                    $SignatureData = New-Object -TypeName $SignatureObjectType -ArgumentList (@(,$SignatureBytes))

                    $VariableData = [PSCustomObject] @{
                        SignatureOwner = $SignatureOwner
                        SignatureData = $SignatureData
                    }
                } else {
                    # Just return a byte array for unknown/new UEFI variables
                    $VariableData = $SignatureDataBytes
                }

                $Event = [PSCustomObject] @{
                    PSTypeName = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            'EV_EFI_VARIABLE_DRIVER_CONFIG' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $VarMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$EventBytes)
                $VarBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $VarMemoryStream, ([Text.Encoding]::Unicode)

                $VariableName = [Guid] $VarBinaryReader.ReadBytes(16)

                # To-do: These lengths are dependant upon the platform architecture. Currently, I'm only considering 64-bit platforms
                $UnicodeNameLength = $VarBinaryReader.ReadUInt64()
                $VariableDataLength = $VarBinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($VarBinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                if (@('PK', 'KEK', 'db', 'dbx') -contains $UnicodeName) {
                    # Parse out the EFI_SIGNATURE_LIST structs

                    $SignatureTypeMapping = @{
                        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
                        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
                    }

                    while ($VarBinaryReader.PeekChar() -ne -1) {
                        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $VarBinaryReader.ReadBytes(16)).Guid]
                        $SignatureListSize = $VarBinaryReader.ReadUInt32()
                        $SignatureHeaderSize = $VarBinaryReader.ReadUInt32()
                        $SignatureSize = $VarBinaryReader.ReadUInt32()

                        $null = $VarBinaryReader.ReadBytes($SignatureHeaderSize) # SignatureHeader

                        # 0x1C is the size of the EFI_SIGNATURE_LIST header
                        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

                        $Signature = 1..$SignatureCount | ForEach-Object {
                            $SignatureDataBytes = $VarBinaryReader.ReadBytes($SignatureSize)

                            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

                            switch ($SignatureType) {
                                'EFI_CERT_SHA256_GUID' {
                                    $SignatureData = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                                }

                                'EFI_CERT_X509_GUID' {
                                    $SignatureData = New-Object $SignatureObjectType -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                                }
                            }

                            [PSCustomObject] @{
                                PSTypeName = 'EFI.SignatureData'
                                SignatureOwner = $SignatureOwner
                                SignatureData = $SignatureData
                            }
                        }

                        $VariableData = [PSCustomObject] @{
                            SignatureType = $SignatureType
                            Signature = $Signature
                        }
                    }
                } else {
                    $VariableData = $VarBinaryReader.ReadBytes($VariableDataLength)
                }

                $VarBinaryReader.Close()

                $Event = [PSCustomObject] @{
                    PSTypeName = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            'EV_EFI_BOOT_SERVICES_APPLICATION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $ImageLocationInMemory = [BitConverter]::ToUInt64($EventBytes, 0)
                $ImageLengthInMemory = [BitConverter]::ToUInt64($EventBytes, 8)
                $ImageLinkTimeAddress = [BitConverter]::ToUInt64($EventBytes, 16)
                $LengthOfDevicePath = [BitConverter]::ToUInt64($EventBytes, 24)

                $DevicePathBytes = $EventBytes[32..(32 + $LengthOfDevicePath - 1)]

                $FilePathList = $null

                # Parse all the file list entries
                if ($DevicePathBytes.Count) {
                    $MoreToParse = $True
                    $FilePathEntryIndex = 0

                    $FilePathList = while ($MoreToParse) {
                        # Parse the EFI_DEVICE_PATH_PROTOCOL struct.

                        $DevicePathType = $DevicePathTypeMapping[$DevicePathBytes[$FilePathEntryIndex]]
                        $Length = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 2)
                        [Byte[]] $DataBytes = $DevicePathBytes[($FilePathEntryIndex + 4)..($FilePathEntryIndex + $Length - 1)]

                        switch ($DevicePathType) {
                            'ACPI_DEVICE_PATH' {
                                $DeviceSubType = $ACPIDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                                switch ($DeviceSubType) {
                                    'ACPI_DP' {
                                        $HID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                                        $UID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 4)

                                        $DeviceInfo = [PSCustomObject] @{
                                            HID = $HID # Device's PnP hardware ID stored in a numeric 32-bit
                                                       # compressed EISA-type ID. This value must match the
                                                       # corresponding _HID in the ACPI name space.
                                            UID = $UID # Unique ID that is required by ACPI if two devices have the
                                                       # same _HID. This value must also match the corresponding
                                                       # _UID/_HID pair in the ACPI name space.
                                        }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }

                                    'ACPI_EXTENDED_DP' {
                                        $HID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                                        $UID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 4)
                                        $CID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 8)

                                        $DeviceInfo = [PSCustomObject] @{
                                            HID = $HID
                                            UID = $UID
                                            CID = $CID # Device's compatible PnP hardware ID stored in a numeric
                                                       # 32-bit compressed EISA-type ID.
                                        }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }

                                    'ACPI_ADR_DP' {
                                        $ADR = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)

                                        $DeviceInfo = [PSCustomObject] @{
                                            ADR = $ADR # For video output devices the value of this
                                                       # field comes from Table B-2 of the ACPI 3.0 specification.
                                        }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }
                                }
                            }

                            'MEDIA_DEVICE_PATH' {
                                $DeviceSubType = $MediaDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                                switch ($DeviceSubType) {
                                    'MEDIA_HARDDRIVE_DP' {
                                        $PartitionNumber = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                                        $PartitionStart = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 4)
                                        $PartitionSize = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 4 + 8)

                                        $SignatureIndex = $FilePathEntryIndex + 4 + 4 + 8 + 8
                                        [Byte[]] $SignatureBytes = $DevicePathBytes[$SignatureIndex..($SignatureIndex + 16 - 1)]
                                        $MBRType = @{ [Byte] 1 = 'MBR_TYPE_PCAT'; [Byte] 2 = 'MBR_TYPE_EFI_PARTITION_TABLE_HEADER' }[$DevicePathBytes[$SignatureIndex + 16]]
                                        $SignatureType = @{ [Byte] 0 = 'NO_DISK_SIGNATURE'; [Byte] 1 = 'SIGNATURE_TYPE_MBR'; [Byte] 2 = 'SIGNATURE_TYPE_GUID' }[$DevicePathBytes[$SignatureIndex + 16 + 1]]

                                        $DeviceInfo = [PSCustomObject] @{
                                            PartitionNumber = $PartitionNumber
                                            PartitionStart = $PartitionStart
                                            PartitionSize = $PartitionSize
                                            Signature = ($SignatureBytes | ForEach-Object {$_.ToString('X2')}) -join ':'
                                            MBRType = $MBRType
                                            SignatureType = $SignatureType
                                        }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }


                                    'MEDIA_FILEPATH_DP' {
                                        $PathName = [Text.Encoding]::Unicode.GetString($DataBytes).TrimEnd(@(0))
                                        $DeviceInfo = [PSCustomObject] @{ PathName = $PathName }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }

                                    'MEDIA_PIWG_FW_VOL_DP' {
                                        $DeviceInfo = [PSCustomObject] @{ FvName = [Guid] $DataBytes }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }

                                    'MEDIA_PIWG_FW_FILE_DP' {
                                        $DeviceInfo = [PSCustomObject] @{ FvFileName = [Guid] $DataBytes }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }

                                    default {
                                        $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')
                                        $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                                        [PSCustomObject] @{
                                            Type = $DevicePathType
                                            SubType = $DeviceSubType
                                            DeviceInfo = $DeviceInfo
                                        }
                                    }
                                }
                            }

                            'END_DEVICE_PATH_TYPE' { }

                            default {
                                # Until other subtypes are added, just supply the bytes.
                                $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')

                                [PSCustomObject] @{
                                    Type = $DevicePathType
                                    SubType = $DeviceSubType
                                    Length = $Length
                                    Data = ($DataBytes | ForEach-Object {$_.ToString('X2')}) -join ':'
                                }
                            }
                        }

                        $FilePathEntryIndex = $FilePathEntryIndex + $Length
                        $MoreToParse = $null -ne $DevicePathBytes[$FilePathEntryIndex]
                    }
                }

                $Event = [PSCustomObject] @{
                    ImageLocationInMemory = $ImageLocationInMemory
                    ImageLengthInMemory = $ImageLengthInMemory
                    ImageLinkTimeAddress = $ImageLinkTimeAddress
                    DevicePath = $FilePathList
                }
            }

            'EV_EFI_ACTION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $Event = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_EFI_VARIABLE_BOOT' {
                $VariableName = [Guid] $BinaryReader.ReadBytes(16)

                $UnicodeNameLength = $BinaryReader.ReadUInt64()
                $VariableDataLength = $BinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($BinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                if ($UnicodeName -eq 'BootOrder') {
                    $VariableData = 1..($VariableDataLength / 2) | ForEach-Object { $BinaryReader.ReadUInt16().ToString('X4') }
                } elseif ($UnicodeName -match '^Boot[0-9A-F]{4}$') {
                    $VariableDataBytes = $BinaryReader.ReadBytes($VariableDataLength)

                    $Attributes = [BitConverter]::ToUInt32($VariableDataBytes, 0)
                    $FilePathListLength = [BitConverter]::ToUInt16($VariableDataBytes, 4)

                    $Index = 6

                    $DescriptionChars = do {
                        $CharVal = [BitConverter]::ToUInt16($VariableDataBytes, $index)
                        [Char] $CharVal

                        $Index += 2
                    } while ($CharVal -ne 0)

                    [String] $Description = $DescriptionChars -join ''

                    $FilePathListEndIndex = $Index + $FilePathListLength - 1
                    # This will be of type: EFI_DEVICE_PATH_PROTOCOL
                    [Byte[]] $FilePathListBytes = $VariableDataBytes[$Index..$FilePathListEndIndex]
                    $FilePathList = $null

                    # Parse all the file list entries
                    if ($FilePathListBytes.Count) {
                        $MoreToParse = $True
                        $FilePathEntryIndex = 0

                        $FilePathList = while ($MoreToParse) {
                            # Parse the EFI_DEVICE_PATH_PROTOCOL struct.

                            $DevicePathType = $DevicePathTypeMapping[$FilePathListBytes[$FilePathEntryIndex]]
                            $Length = [BitConverter]::ToUInt16($FilePathListBytes, $FilePathEntryIndex + 2)
                            [Byte[]] $DataBytes = $FilePathListBytes[($FilePathEntryIndex + 4)..($FilePathEntryIndex + $Length - 1)]

                            switch ($DevicePathType) {
                                'MEDIA_DEVICE_PATH' {
                                    $DeviceSubType = $MediaDeviceSubTypeMapping[$FilePathListBytes[$FilePathEntryIndex + 1]]

                                    switch ($DeviceSubType) {
                                        'MEDIA_HARDDRIVE_DP' {
                                            $PartitionNumber = [BitConverter]::ToUInt32($FilePathListBytes, $FilePathEntryIndex + 4 + 0)
                                            $PartitionStart = [BitConverter]::ToUInt64($FilePathListBytes, $FilePathEntryIndex + 4 + 4)
                                            $PartitionSize = [BitConverter]::ToUInt64($FilePathListBytes, $FilePathEntryIndex + 4 + 4 + 8)

                                            $SignatureIndex = $FilePathEntryIndex + 4 + 4 + 8 + 8
                                            [Byte[]] $SignatureBytes = $FilePathListBytes[$SignatureIndex..($SignatureIndex + 16 - 1)]
                                            $MBRType = @{ [Byte] 1 = 'MBR_TYPE_PCAT'; [Byte] 2 = 'MBR_TYPE_EFI_PARTITION_TABLE_HEADER' }[$FilePathListBytes[$SignatureIndex + 16]]
                                            $SignatureType = @{ [Byte] 0 = 'NO_DISK_SIGNATURE'; [Byte] 1 = 'SIGNATURE_TYPE_MBR'; [Byte] 2 = 'SIGNATURE_TYPE_GUID' }[$FilePathListBytes[$SignatureIndex + 16 + 1]]

                                            $DeviceInfo = [PSCustomObject] @{
                                                PartitionNumber = $PartitionNumber
                                                PartitionStart = $PartitionStart
                                                PartitionSize = $PartitionSize
                                                Signature = ($SignatureBytes | ForEach-Object {$_.ToString('X2')}) -join ':'
                                                MBRType = $MBRType
                                                SignatureType = $SignatureType
                                            }

                                            [PSCustomObject] @{
                                                Type = $DevicePathType
                                                SubType = $DeviceSubType
                                                DeviceInfo = $DeviceInfo
                                            }
                                        }


                                        'MEDIA_FILEPATH_DP' {
                                            $PathName = [Text.Encoding]::Unicode.GetString($DataBytes).TrimEnd(@(0))
                                            $DeviceInfo = [PSCustomObject] @{ PathName = $PathName }

                                            [PSCustomObject] @{
                                                Type = $DevicePathType
                                                SubType = $DeviceSubType
                                                DeviceInfo = $DeviceInfo
                                            }
                                        }

                                        'MEDIA_PIWG_FW_VOL_DP' {
                                            $DeviceInfo = [PSCustomObject] @{ FvName = [Guid] $DataBytes }

                                            [PSCustomObject] @{
                                                Type = $DevicePathType
                                                SubType = $DeviceSubType
                                                DeviceInfo = $DeviceInfo
                                            }
                                        }

                                        'MEDIA_PIWG_FW_FILE_DP' {
                                            $DeviceInfo = [PSCustomObject] @{ FvFileName = [Guid] $DataBytes }

                                            [PSCustomObject] @{
                                                Type = $DevicePathType
                                                SubType = $DeviceSubType
                                                DeviceInfo = $DeviceInfo
                                            }
                                        }

                                        default {
                                            $DeviceSubType = $FilePathListBytes[$FilePathEntryIndex + 1].ToString('X2')
                                            $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                                            [PSCustomObject] @{
                                                Type = $DevicePathType
                                                SubType = $DeviceSubType
                                                DeviceInfo = $DeviceInfo
                                            }
                                        }
                                    }
                                }

                                'END_DEVICE_PATH_TYPE' { }

                                default {
                                    # Until other subtypes are added, just supply the bytes.
                                    $DeviceSubType = $FilePathListBytes[$FilePathEntryIndex + 1].ToString('X2')

                                    [PSCustomObject] @{
                                        Type = $DevicePathType
                                        SubType = $DeviceSubType
                                        Length = $Length
                                        Data = ($DataBytes | ForEach-Object {$_.ToString('X2')}) -join ':'
                                    }
                                }
                            }

                            $FilePathEntryIndex = $FilePathEntryIndex + $Length
                            $MoreToParse = $null -ne $FilePathListBytes[$FilePathEntryIndex]
                        }
                    }

                    $OptionalData = $null

                    # The remaining bytes in the load option descriptor are a binary data buffer that is passed to the loaded image.
                    # If the field is zero bytes long, a NULL pointer is passed to the loaded image. The number of bytes in OptionalData
                    # can be computed by subtracting the starting offset of OptionalData from total size in bytes of the EFI_LOAD_OPTION.
                    if (($VariableDataBytes.Count - ($FilePathListEndIndex + 1)) -gt 0) { $OptionalData = $VariableDataBytes[($FilePathListEndIndex + 1)..($VariableDataBytes.Count - 1)] }

                    if ($OptionalData) { $OptionalData = ($OptionalData | ForEach-Object {$_.ToString('X2')}) -join ':' }

                    $VariableData = [PSCustomObject] @{
                        Attributes = $Attributes
                        FilePathListLength = $FilePathListLength
                        Description = $Description.TrimEnd(@(0))
                        FilePathList = $FilePathList
                        OptionalData = $OptionalData
                    }
                } else {
                    $VariableData = $BinaryReader.ReadBytes($VariableDataLength)
                }

                $Event = [PSCustomObject] @{
                    PSTypeName = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            default {
                $Event = ($BinaryReader.ReadBytes($EventSize) | ForEach-Object {$_.ToString('X2')}) -join ':'
            }
        }

        [Ordered] @{
            PCR = $PCRIndex
            EventType = $EventType
            Digest = $Digests
            Event = $Event
        }
    }

    $BinaryReader.Close()

    $PCRTemplate = [Ordered] @{
        PCR0 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR1 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR2 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR3 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR4 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR5 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR6 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR7 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR8 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR9 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR10 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR11 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR12 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR13 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR14 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR15 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR16 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR23 = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCRMinusOne = (New-Object 'System.Collections.Generic.List[PSObject]')
    }

    foreach ($PCRMeasurement in $Events) {
        if ($PCRMeasurement['PCR'] -eq -1) {
            $PCRMeasurement.Remove('PCR')
            $PCRTemplate['PCRMinusOne'].Add(([PSCustomObject] $PCRMeasurement))
        } else {
            $PCRNum = $PCRMeasurement['PCR']
            $PCRMeasurement.Remove('PCR')
            $PCRTemplate["PCR$($PCRNum)"].Add(([PSCustomObject] $PCRMeasurement))
        }
    }

    foreach ($Key in $PCRTemplate.GetEnumerator().Name) {
        if ($PCRTemplate[$Key].Count -eq 0) { $PCRTemplate[$Key] = $null }
        if ($PCRTemplate[$Key].Count -eq 1) { $PCRTemplate[$Key] = $PCRTemplate[$Key][0] }
    }

    $TCGEventLog = [PSCustomObject] @{
        PSTypeName = 'TCGLog'
        LogPath = $LogFullPath
        Header = $TCGHeader
        Events = ([PSCustomObject] $PCRTemplate)
    }

    $TCGEventLog
}

Export-ModuleMember -Function Get-TCGLogContent, ConvertTo-TCGEventLog, Get-TPMDeviceInfo
