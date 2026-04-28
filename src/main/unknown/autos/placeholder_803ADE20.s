.include "macros.inc"

.section .bss, "wa", @nobits

.balign 8
.global CommandList_803ADE20
CommandList:
CommandList_803ADE20:
    .skip 0x3C

.hidden gap_08_803ADE5C_bss
gap_08_803ADE5C_bss:
    .skip 0x2C

.global AlarmForTimeout_803ADE88
AlarmForTimeout:
AlarmForTimeout_803ADE88:
    .skip 0x28

.hidden gap_08_803ADEB0_bss
gap_08_803ADEB0_bss:
    .skip 0x40
