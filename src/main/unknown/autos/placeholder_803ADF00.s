.include "macros.inc"

.section .bss, "wa", @nobits

.balign 8
.global tmpBuffer_803ADF00
tmpBuffer:
tmpBuffer_803ADF00:
    .skip 0x80

.global DummyCommandBlock_803ADF80
DummyCommandBlock:
DummyCommandBlock_803ADF80:
    .skip 0x30

.hidden gap_08_803ADFB0_bss
gap_08_803ADFB0_bss:
    .skip 0x28
