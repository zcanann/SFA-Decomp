/* TODO: restore stripped imported address metadata if needed. */

.include "macros.inc"
.file "__exception"

.section .init, "ax"
.balign 4

# The MetroTRK exception vector table occupies this block in SFA EN 1.0.
# Keep the raw vector bytes until the individual handlers are recovered.
.global gTRKInterruptVectorTable
gTRKInterruptVectorTable:
.fn pad_00_80003538_init, local
.incbin "orig/GSAE01/sys/main.dol", 0x538, 0x1F34
.endfn pad_00_80003538_init

.global gTRKInterruptVectorTableEnd
gTRKInterruptVectorTableEnd:

.fn __TRK_reset, global
stwu r1, -0x20(r1)
mflr r0
lis r3, lc_base@ha
stw r0, 0x24(r1)
addi r3, r3, lc_base@l
stmw r27, 0xc(r1)
lwz r3, 0x0(r3)
cmplwi r3, 0x44
bgt .L_800054B8
addi r0, r3, 0x4000
cmplwi r0, 0x44
ble .L_800054B8
lis r3, gTRKCPUState@ha
addi r3, r3, gTRKCPUState@l
lwz r0, 0x238(r3)
clrlwi. r0, r0, 30
beq .L_800054B8
li r5, 0x44
b .L_800054C0
.L_800054B8:
lis r3, 0x8000
addi r5, r3, 0x44
.L_800054C0:
lis r4, TRK_ISR_OFFSETS@ha
lis r3, gTRKCPUState@ha
lwz r29, 0x0(r5)
addi r31, r4, TRK_ISR_OFFSETS@l
addi r30, r3, gTRKCPUState@l
li r28, 0x0
.L_800054D8:
li r0, 0x1
slw r0, r0, r28
and. r0, r29, r0
beq .L_8000554C
lis r3, lc_base@ha
lwz r6, 0x0(r31)
addi r3, r3, lc_base@l
lwz r3, 0x0(r3)
cmplw r6, r3
blt .L_80005520
addi r0, r3, 0x4000
cmplw r6, r0
bge .L_80005520
lwz r0, 0x238(r30)
clrlwi. r0, r0, 30
beq .L_80005520
mr r27, r6
b .L_80005528
.L_80005520:
clrlwi r0, r6, 2
oris r27, r0, 0x8000
.L_80005528:
lis r4, gTRKInterruptVectorTable@ha
mr r3, r27
addi r0, r4, gTRKInterruptVectorTable@l
li r5, 0x100
add r4, r0, r6
bl TRK_memcpy
mr r3, r27
li r4, 0x100
bl TRK_flush_cache
.L_8000554C:
addi r28, r28, 0x1
addi r31, r31, 0x4
cmpwi r28, 0xe
ble .L_800054D8
lmw r27, 0xc(r1)
lwz r0, 0x24(r1)
mtlr r0
addi r1, r1, 0x20
blr
.endfn __TRK_reset
