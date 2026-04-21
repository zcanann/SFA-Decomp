#include <math.h>

#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

static struct {
    GXVtxDescList vcd[27];
    GXVtxAttrFmtList vat[27];
} lbl_803AF698;

#define vcd lbl_803AF698.vcd
#define vat lbl_803AF698.vat

extern const f32 lbl_803E83C8;
extern const f32 lbl_803E83E0;
extern const double lbl_803E83D0;
extern const double lbl_803E83D8;

asm void GXDrawTorus(f32 rc, u8 numc, u8 numt) {
    nofralloc
    mflr r0
    lis r5, lbl_803AF698@ha
    stw r0, 0x4(r1)
    stwu r1, -0xb0(r1)
    stfd f31, 0xa8(r1)
    stfd f30, 0xa0(r1)
    stfd f29, 0x98(r1)
    stfd f28, 0x90(r1)
    stfd f27, 0x88(r1)
    stfd f26, 0x80(r1)
    fmr f26, f1
    stfd f25, 0x78(r1)
    stfd f24, 0x70(r1)
    stfd f23, 0x68(r1)
    stmw r20, 0x38(r1)
    addi r21, r3, 0x0
    addi r20, r4, 0x0
    addi r31, r5, lbl_803AF698@l
    addi r4, r1, 0x10
    li r3, 0xd
    lfs f0, lbl_803E83C8(r2)
    lfs f28, lbl_803E83E0(r2)
    fsubs f27, f0, f26
    bl GXGetVtxDesc
    mr r3, r31
    bl GXGetVtxDescv
    li r3, 0x3
    addi r4, r31, 0xd8
    bl GXGetVtxAttrFmtv
    bl GXClearVtxDesc
    li r3, 0x9
    li r4, 0x1
    bl GXSetVtxDesc
    li r3, 0xa
    li r4, 0x1
    bl GXSetVtxDesc
    li r3, 0x3
    li r4, 0x9
    li r5, 0x1
    li r6, 0x4
    li r7, 0x0
    bl GXSetVtxAttrFmt
    li r3, 0x3
    li r4, 0xa
    li r5, 0x0
    li r6, 0x4
    li r7, 0x0
    bl GXSetVtxAttrFmt
    lwz r0, 0x10(r1)
    cmpwi r0, 0x0
    beq _gdt_0
    li r3, 0xd
    li r4, 0x1
    bl GXSetVtxDesc
    li r3, 0x3
    li r4, 0xd
    li r5, 0x1
    li r6, 0x4
    li r7, 0x0
    bl GXSetVtxAttrFmt
_gdt_0:
    clrlwi r28, r20, 24
    lfd f30, lbl_803E83D0(r2)
    addi r0, r28, 0x1
    lfd f31, lbl_803E83D8(r2)
    slwi r30, r0, 1
    clrlwi r29, r21, 24
    li r27, 0x0
    lis r21, 0x4330
    lis r23, 0xcc01
    b _gdt_6
_gdt_1:
    clrlwi r5, r30, 16
    li r3, 0x98
    li r4, 0x3
    bl GXBegin
    li r26, 0x0
    b _gdt_5
_gdt_2:
    divw r0, r26, r28
    mullw r0, r0, r28
    subf r0, r0, r26
    xoris r22, r0, 0x8000
    xoris r24, r26, 0x8000
    li r25, 0x1
_gdt_3:
    add r20, r27, r25
    stw r22, 0x2c(r1)
    divw r0, r20, r29
    stw r21, 0x28(r1)
    stw r28, 0x24(r1)
    lfd f0, 0x28(r1)
    stw r21, 0x20(r1)
    fsubs f1, f0, f30
    lfd f0, 0x20(r1)
    mullw r0, r0, r29
    fsubs f0, f0, f31
    fmuls f1, f1, f28
    fdivs f29, f1, f0
    subf r0, r0, r20
    xoris r0, r0, 0x8000
    stw r0, 0x34(r1)
    stw r21, 0x30(r1)
    lfd f0, 0x30(r1)
    fmr f1, f29
    fsubs f23, f0, f30
    bl cosf
    stw r29, 0x1c(r1)
    fmuls f2, f23, f28
    fmr f25, f1
    stw r21, 0x18(r1)
    lfd f0, 0x18(r1)
    fsubs f0, f0, f31
    fdivs f24, f2, f0
    fmr f1, f24
    bl cosf
    fmuls f0, f26, f1
    fmr f1, f29
    fsubs f0, f27, f0
    fmuls f23, f0, f25
    bl sinf
    fmr f25, f1
    fmr f1, f24
    bl cosf
    fmuls f0, f26, f1
    fmr f1, f24
    fsubs f0, f27, f0
    fmuls f25, f0, f25
    bl sinf
    stfs f23, -0x8000(r23)
    fmuls f0, f26, f1
    fmr f1, f24
    stfs f25, -0x8000(r23)
    stfs f0, -0x8000(r23)
    bl cosf
    fmr f25, f1
    fmr f1, f29
    bl cosf
    fneg f0, f1
    fmr f1, f24
    fmuls f23, f0, f25
    bl cosf
    fmr f25, f1
    fmr f1, f29
    bl sinf
    fneg f0, f1
    fmr f1, f24
    fmuls f24, f0, f25
    bl sinf
    stfs f23, -0x8000(r23)
    lwz r0, 0x10(r1)
    stfs f24, -0x8000(r23)
    cmpwi r0, 0x0
    stfs f1, -0x8000(r23)
    beq _gdt_4
    xoris r0, r20, 0x8000
    stw r29, 0x24(r1)
    stw r0, 0x1c(r1)
    stw r21, 0x18(r1)
    stw r21, 0x20(r1)
    lfd f1, 0x18(r1)
    stw r24, 0x2c(r1)
    lfd f0, 0x20(r1)
    fsubs f1, f1, f30
    stw r28, 0x34(r1)
    fsubs f0, f0, f31
    stw r21, 0x28(r1)
    stw r21, 0x30(r1)
    fdivs f2, f1, f0
    lfd f1, 0x28(r1)
    lfd f0, 0x30(r1)
    fsubs f1, f1, f30
    stfs f2, -0x8000(r23)
    fsubs f0, f0, f31
    fdivs f0, f1, f0
    stfs f0, -0x8000(r23)
_gdt_4:
    subic. r25, r25, 0x1
    bge _gdt_3
    addi r26, r26, 0x1
_gdt_5:
    cmpw r26, r28
    ble _gdt_2
    addi r27, r27, 0x1
_gdt_6:
    cmpw r27, r29
    blt _gdt_1
    mr r3, r31
    bl GXSetVtxDescv
    li r3, 0x3
    addi r4, r31, 0xd8
    bl GXSetVtxAttrFmtv
    lmw r20, 0x38(r1)
    lwz r0, 0xb4(r1)
    lfd f31, 0xa8(r1)
    lfd f30, 0xa0(r1)
    lfd f29, 0x98(r1)
    lfd f28, 0x90(r1)
    lfd f27, 0x88(r1)
    lfd f26, 0x80(r1)
    lfd f25, 0x78(r1)
    lfd f24, 0x70(r1)
    lfd f23, 0x68(r1)
    addi r1, r1, 0xb0
    mtlr r0
    blr
}
