.include "macros.inc"

.section .sdata, "wa"

.balign 4
.global lbl_803DC630
lbl_803DC630:
    .4byte 0x80000000
    .4byte 0x00000000

.section .sbss, "wa"

.balign 4
.global lbl_803DE3C8
lbl_803DE3C8:
    .skip 0x4

.global lbl_803DE3CC
lbl_803DE3CC:
    .skip 0x4

.global lbl_803DE3D0
lbl_803DE3D0:
    .skip 0x4

.global lbl_803DE3D4
lbl_803DE3D4:
    .skip 0x4

.global lbl_803DE3D8
lbl_803DE3D8:
    .skip 0x4

.global lbl_803DE3DC
lbl_803DE3DC:
    .skip 0x1

.hidden gap_10_803DE3DD_sbss
gap_10_803DE3DD_sbss:
    .skip 0x3
