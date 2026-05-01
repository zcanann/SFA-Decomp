.include "macros.inc"

.global OSStringBase_8032C360
.set OSStringBase_8032C360, 0x8032C360

.section .bss, "wa", @nobits

.balign 8
.global DriveInfo_803AD320
DriveInfo:
DriveInfo_803AD320:
    .skip 0x20

.hidden gap_08_803AD340_bss
gap_08_803AD340_bss:
    .skip 0x30

.section .sbss, "wa", @nobits

.balign 8
.global BootInfo_803DDDD8
BootInfo:
BootInfo_803DDDD8:
    .skip 0x4

.global BI2DebugFlag_803DDDDC
BI2DebugFlag:
BI2DebugFlag_803DDDDC:
    .skip 0x4

.global BI2DebugFlagHolder_803DDDE0
BI2DebugFlagHolder:
BI2DebugFlagHolder_803DDDE0:
    .skip 0x4

.global __OSIsGcam
__OSIsGcam:
    .skip 0x4

.global AreWeInitialized_803DDDE8
AreWeInitialized:
AreWeInitialized_803DDDE8:
    .skip 0x4

.global OSExceptionTable_803DDDEC
OSExceptionTable:
OSExceptionTable_803DDDEC:
    .skip 0x4

.global __OSSavedRegionEnd
__OSSavedRegionEnd:
    .skip 0x4

.global __OSSavedRegionStart
__OSSavedRegionStart:
    .skip 0x4

.global __OSInIPL
__OSInIPL:
    .skip 0x4

.hidden gap_10_803DDDFC_sbss
gap_10_803DDDFC_sbss:
    .skip 0x4

.global __OSStartTime
__OSStartTime:
    .skip 0x8
