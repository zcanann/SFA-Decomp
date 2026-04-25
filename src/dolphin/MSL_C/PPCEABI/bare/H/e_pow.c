/*
 * Target bytes at 0x80294BB8..0x80295334 are not Sun's MSL __ieee754_pow.
 * Custom 480-instruction pow(x,y) implementation. Asm-only.
 */

#include "dolphin.h"

extern const float lbl_803E7E50;
extern const float lbl_803E7E54;
extern const float lbl_803E7E58;
extern const double lbl_803E7E60;
extern unsigned int lbl_803DC648;
extern unsigned int lbl_803DC64C;
extern unsigned int lbl_803DC650;
extern unsigned int lbl_803DC658;
extern unsigned int lbl_803DC65C;
extern unsigned char lbl_80332A28;
extern unsigned char lbl_80332C78;

asm float __ieee754_pow(float x, float y) {
    nofralloc
    stwu r1, -0x90(r1)
    stfs f1, 0x8(r1)
    lfs f1, 0x8(r1)
    lis r3, lbl_80332C78@ha
    lfs f3, lbl_803E7E50(r0)
    addi r3, r3, lbl_80332C78@l
    fcmpo cr0, f1, f3
    ble _ep_80294dc0
    stfs f1, 0x60(r1)
    lwz r0, lbl_803DC658(r0)
    lwz r9, 0x60(r1)
    stw r0, 0x68(r1)
    clrlwi r0, r9, 16
    lwz r5, lbl_803DC65C(r0)
    cmplwi r0, 0x0
    srwi r4, r9, 23
    stw r5, 0x6c(r1)
    clrlwi r6, r9, 9
    subi r8, r4, 0x80
    srwi r7, r6, 16
    beq _ep_80294cc0
    rlwinm r4, r9, 0, 9, 15
    rlwinm r0, r9, 0, 16, 16
    oris r5, r4, 0x3f80
    oris r4, r6, 0x3f80
    stw r5, 0x64(r1)
    cmplwi r0, 0x0
    stw r4, 0x74(r1)
    beq _ep_80294c3c
    lwz r4, 0x64(r1)
    addi r7, r7, 0x1
    addis r0, r4, 0x1
    stw r0, 0x64(r1)
_ep_80294c3c:
    lis r4, lbl_80332A28@ha
    lfs f3, 0x74(r1)
    lfs f0, 0x64(r1)
    slwi r5, r7, 2
    addi r0, r4, lbl_80332A28@l
    lfs f1, 0x6c(r1)
    add r4, r0, r5
    fsubs f7, f3, f0
    lfs f3, 0x0(r4)
    addi r4, r13, -0x6B90
    lfs f0, 0x68(r1)
    xoris r0, r8, 0x8000
    fmuls f7, f7, f3
    lfs f4, 0x4(r4)
    stw r0, 0x8c(r1)
    lis r0, 0x4330
    lfs f5, lbl_803DC650(r0)
    fmuls f3, f7, f7
    stw r0, 0x88(r1)
    fmadds f0, f7, f1, f0
    lfd f6, lbl_803E7E60(r0)
    lfd f1, 0x88(r1)
    fmuls f0, f3, f0
    lfs f3, lbl_803E7E54(r0)
    fsubs f6, f1, f6
    lfsx f1, r3, r5
    fmadds f0, f4, f7, f0
    fadds f3, f6, f3
    fmadds f0, f5, f7, f0
    fadds f0, f7, f0
    fadds f0, f1, f0
    fadds f0, f3, f0
    b _ep_80294cf0
_ep_80294cc0:
    xoris r0, r8, 0x8000
    lfd f4, lbl_803E7E60(r0)
    stw r0, 0x8c(r1)
    lis r4, 0x4330
    slwi r0, r7, 2
    lfs f1, lbl_803E7E54(r0)
    stw r4, 0x88(r1)
    lfsx f0, r3, r0
    lfd f3, 0x88(r1)
    fsubs f3, f3, f4
    fadds f1, f3, f1
    fadds f0, f1, f0
_ep_80294cf0:
    fmuls f2, f2, f0
    lis r0, 0x4330
    lfd f1, lbl_803E7E60(r0)
    fctiwz f0, f2
    stfd f0, 0x88(r1)
    lwz r4, 0x8c(r1)
    stw r4, 0x58(r1)
    lwz r5, 0x58(r1)
    xoris r4, r5, 0x8000
    stw r4, 0x84(r1)
    cmpwi r5, 0x80
    stw r0, 0x80(r1)
    lfd f0, 0x80(r1)
    fsubs f0, f0, f1
    fsubs f8, f2, f0
    ble _ep_80294d40
    lis r3, lbl_803DC64C@ha
    addi r3, r3, lbl_803DC64C@l
    lfs f1, 0x0(r3)
    b _ep_80294dbc
_ep_80294d40:
    cmpwi r5, -0x7f
    bge _ep_80294d50
    lfs f1, lbl_803E7E50(r0)
    b _ep_80294dbc
_ep_80294d50:
    addi r0, r5, 0x7f
    lfs f0, lbl_803E7E58(r0)
    stw r0, 0x58(r1)
    lwz r0, 0x58(r1)
    slwi r0, r0, 23
    stw r0, 0x58(r1)
    lfs f3, 0x224(r3)
    lfs f1, 0x220(r3)
    lfs f2, 0x21c(r3)
    fmadds f3, f8, f3, f1
    lfs f1, 0x218(r3)
    lfs f5, 0x214(r3)
    lfs f4, 0x210(r3)
    fmadds f6, f8, f3, f2
    lfs f3, 0x20c(r3)
    lfs f2, 0x208(r3)
    fmadds f6, f8, f6, f1
    lfs f1, 0x204(r3)
    lfs f7, 0x58(r1)
    fmadds f5, f8, f6, f5
    fmadds f4, f8, f5, f4
    fmadds f3, f8, f4, f3
    fmadds f2, f8, f3, f2
    fmadds f1, f8, f2, f1
    fmuls f1, f8, f1
    fadds f0, f1, f0
    fmuls f1, f7, f0
_ep_80294dbc:
    b _ep_8029532c
_ep_80294dc0:
    bge _ep_802951f4
    fctiwz f0, f2
    lis r5, 0x4330
    lfd f4, lbl_803E7E60(r0)
    stfd f0, 0x88(r1)
    lwz r0, 0x8c(r1)
    stfd f0, 0x80(r1)
    xoris r0, r0, 0x8000
    stw r0, 0x7c(r1)
    lwz r4, 0x84(r1)
    stw r5, 0x78(r1)
    lfd f0, 0x78(r1)
    fsubs f0, f0, f4
    fsubs f0, f2, f0
    fcmpu cr0, f0, f3
    beq _ep_80294e10
    lis r3, lbl_803DC648@ha
    addi r3, r3, lbl_803DC648@l
    lfs f1, 0x0(r3)
    b _ep_8029532c
_ep_80294e10:
    srawi r0, r4, 1
    addze r0, r0
    slwi r0, r0, 1
    subfc r0, r0, r4
    cmpwi r0, 0x0
    beq _ep_80295010
    fneg f0, f1
    lwz r4, lbl_803DC658(r0)
    lwz r0, lbl_803DC65C(r0)
    stw r4, 0x48(r1)
    stfs f0, 0x40(r1)
    lwz r9, 0x40(r1)
    stw r0, 0x4c(r1)
    clrlwi r0, r9, 16
    srwi r4, r9, 23
    clrlwi r6, r9, 9
    cmplwi r0, 0x0
    subi r8, r4, 0x80
    srwi r7, r6, 16
    beq _ep_80294f14
    rlwinm r4, r9, 0, 9, 15
    rlwinm r0, r9, 0, 16, 16
    oris r5, r4, 0x3f80
    oris r4, r6, 0x3f80
    stw r5, 0x44(r1)
    cmplwi r0, 0x0
    stw r4, 0x54(r1)
    beq _ep_80294e90
    lwz r4, 0x44(r1)
    addi r7, r7, 0x1
    addis r0, r4, 0x1
    stw r0, 0x44(r1)
_ep_80294e90:
    lis r4, lbl_80332A28@ha
    lfs f3, 0x54(r1)
    lfs f0, 0x44(r1)
    slwi r5, r7, 2
    addi r0, r4, lbl_80332A28@l
    lfs f1, 0x4c(r1)
    add r4, r0, r5
    fsubs f7, f3, f0
    lfs f3, 0x0(r4)
    addi r4, r13, -0x6B90
    lfs f0, 0x48(r1)
    xoris r0, r8, 0x8000
    fmuls f7, f7, f3
    lfs f4, 0x4(r4)
    stw r0, 0x7c(r1)
    lis r0, 0x4330
    lfs f5, lbl_803DC650(r0)
    fmuls f3, f7, f7
    stw r0, 0x78(r1)
    fmadds f0, f7, f1, f0
    lfd f6, lbl_803E7E60(r0)
    lfd f1, 0x78(r1)
    fmuls f0, f3, f0
    lfs f3, lbl_803E7E54(r0)
    fsubs f6, f1, f6
    lfsx f1, r3, r5
    fmadds f0, f4, f7, f0
    fadds f3, f6, f3
    fmadds f0, f5, f7, f0
    fadds f0, f7, f0
    fadds f0, f1, f0
    fadds f0, f3, f0
    b _ep_80294f3c
_ep_80294f14:
    xoris r0, r8, 0x8000
    lfs f1, lbl_803E7E54(r0)
    stw r0, 0x7c(r1)
    slwi r0, r7, 2
    lfsx f0, r3, r0
    stw r5, 0x78(r1)
    lfd f3, 0x78(r1)
    fsubs f3, f3, f4
    fadds f1, f3, f1
    fadds f0, f1, f0
_ep_80294f3c:
    fmuls f2, f2, f0
    lis r0, 0x4330
    lfd f1, lbl_803E7E60(r0)
    fctiwz f0, f2
    stfd f0, 0x78(r1)
    lwz r4, 0x7c(r1)
    stw r4, 0x38(r1)
    lwz r5, 0x38(r1)
    xoris r4, r5, 0x8000
    stw r4, 0x84(r1)
    cmpwi r5, 0x80
    stw r0, 0x80(r1)
    lfd f0, 0x80(r1)
    fsubs f0, f0, f1
    fsubs f8, f2, f0
    ble _ep_80294f8c
    lis r3, lbl_803DC64C@ha
    addi r3, r3, lbl_803DC64C@l
    lfs f0, 0x0(r3)
    b _ep_80295008
_ep_80294f8c:
    cmpwi r5, -0x7f
    bge _ep_80294f9c
    lfs f0, lbl_803E7E50(r0)
    b _ep_80295008
_ep_80294f9c:
    addi r0, r5, 0x7f
    lfs f0, lbl_803E7E58(r0)
    stw r0, 0x38(r1)
    lwz r0, 0x38(r1)
    slwi r0, r0, 23
    stw r0, 0x38(r1)
    lfs f3, 0x224(r3)
    lfs f1, 0x220(r3)
    lfs f2, 0x21c(r3)
    fmadds f3, f8, f3, f1
    lfs f1, 0x218(r3)
    lfs f5, 0x214(r3)
    lfs f4, 0x210(r3)
    fmadds f6, f8, f3, f2
    lfs f3, 0x20c(r3)
    lfs f2, 0x208(r3)
    fmadds f6, f8, f6, f1
    lfs f1, 0x204(r3)
    lfs f7, 0x38(r1)
    fmadds f5, f8, f6, f5
    fmadds f4, f8, f5, f4
    fmadds f3, f8, f4, f3
    fmadds f2, f8, f3, f2
    fmadds f1, f8, f2, f1
    fmuls f1, f8, f1
    fadds f0, f1, f0
    fmuls f0, f7, f0
_ep_80295008:
    fneg f1, f0
    b _ep_8029532c
_ep_80295010:
    fneg f0, f1
    lwz r4, lbl_803DC658(r0)
    lwz r0, lbl_803DC65C(r0)
    stw r4, 0x28(r1)
    stfs f0, 0x20(r1)
    lwz r9, 0x20(r1)
    stw r0, 0x2c(r1)
    clrlwi r0, r9, 16
    srwi r4, r9, 23
    clrlwi r6, r9, 9
    cmplwi r0, 0x0
    subi r8, r4, 0x80
    srwi r7, r6, 16
    beq _ep_802950fc
    rlwinm r4, r9, 0, 9, 15
    rlwinm r0, r9, 0, 16, 16
    oris r5, r4, 0x3f80
    oris r4, r6, 0x3f80
    stw r5, 0x24(r1)
    cmplwi r0, 0x0
    stw r4, 0x34(r1)
    beq _ep_80295078
    lwz r4, 0x24(r1)
    addi r7, r7, 0x1
    addis r0, r4, 0x1
    stw r0, 0x24(r1)
_ep_80295078:
    lis r4, lbl_80332A28@ha
    lfs f3, 0x34(r1)
    lfs f0, 0x24(r1)
    slwi r5, r7, 2
    addi r0, r4, lbl_80332A28@l
    lfs f1, 0x2c(r1)
    add r4, r0, r5
    fsubs f7, f3, f0
    lfs f3, 0x0(r4)
    addi r4, r13, -0x6B90
    lfs f0, 0x28(r1)
    xoris r0, r8, 0x8000
    fmuls f7, f7, f3
    lfs f4, 0x4(r4)
    stw r0, 0x7c(r1)
    lis r0, 0x4330
    lfs f5, lbl_803DC650(r0)
    fmuls f3, f7, f7
    stw r0, 0x78(r1)
    fmadds f0, f7, f1, f0
    lfd f6, lbl_803E7E60(r0)
    lfd f1, 0x78(r1)
    fmuls f0, f3, f0
    lfs f3, lbl_803E7E54(r0)
    fsubs f6, f1, f6
    lfsx f1, r3, r5
    fmadds f0, f4, f7, f0
    fadds f3, f6, f3
    fmadds f0, f5, f7, f0
    fadds f0, f7, f0
    fadds f0, f1, f0
    fadds f0, f3, f0
    b _ep_80295124
_ep_802950fc:
    xoris r0, r8, 0x8000
    lfs f1, lbl_803E7E54(r0)
    stw r0, 0x7c(r1)
    slwi r0, r7, 2
    lfsx f0, r3, r0
    stw r5, 0x78(r1)
    lfd f3, 0x78(r1)
    fsubs f3, f3, f4
    fadds f1, f3, f1
    fadds f0, f1, f0
_ep_80295124:
    fmuls f2, f2, f0
    lis r0, 0x4330
    lfd f1, lbl_803E7E60(r0)
    fctiwz f0, f2
    stfd f0, 0x78(r1)
    lwz r4, 0x7c(r1)
    stw r4, 0x18(r1)
    lwz r5, 0x18(r1)
    xoris r4, r5, 0x8000
    stw r4, 0x84(r1)
    cmpwi r5, 0x80
    stw r0, 0x80(r1)
    lfd f0, 0x80(r1)
    fsubs f0, f0, f1
    fsubs f8, f2, f0
    ble _ep_80295174
    lis r3, lbl_803DC64C@ha
    addi r3, r3, lbl_803DC64C@l
    lfs f1, 0x0(r3)
    b _ep_802951f0
_ep_80295174:
    cmpwi r5, -0x7f
    bge _ep_80295184
    lfs f1, lbl_803E7E50(r0)
    b _ep_802951f0
_ep_80295184:
    addi r0, r5, 0x7f
    lfs f0, lbl_803E7E58(r0)
    stw r0, 0x18(r1)
    lwz r0, 0x18(r1)
    slwi r0, r0, 23
    stw r0, 0x18(r1)
    lfs f3, 0x224(r3)
    lfs f1, 0x220(r3)
    lfs f2, 0x21c(r3)
    fmadds f3, f8, f3, f1
    lfs f1, 0x218(r3)
    lfs f5, 0x214(r3)
    lfs f4, 0x210(r3)
    fmadds f6, f8, f3, f2
    lfs f3, 0x20c(r3)
    lfs f2, 0x208(r3)
    fmadds f6, f8, f6, f1
    lfs f1, 0x204(r3)
    lfs f7, 0x18(r1)
    fmadds f5, f8, f6, f5
    fmadds f4, f8, f5, f4
    fmadds f3, f8, f4, f3
    fmadds f2, f8, f3, f2
    fmadds f1, f8, f2, f1
    fmuls f1, f8, f1
    fadds f0, f1, f0
    fmuls f1, f7, f0
_ep_802951f0:
    b _ep_8029532c
_ep_802951f4:
    stfs f1, 0x14(r1)
    lis r0, 0x7f80
    lwz r4, 0x14(r1)
    rlwinm r3, r4, 0, 1, 8
    cmpw r3, r0
    beq _ep_8029521c
    bge _ep_80295254
    cmpwi r3, 0x0
    beq _ep_80295238
    b _ep_80295254
_ep_8029521c:
    clrlwi r0, r4, 9
    cmpwi r0, 0x0
    beq _ep_80295230
    li r0, 0x1
    b _ep_80295258
_ep_80295230:
    li r0, 0x2
    b _ep_80295258
_ep_80295238:
    clrlwi r0, r4, 9
    cmpwi r0, 0x0
    beq _ep_8029524c
    li r0, 0x5
    b _ep_80295258
_ep_8029524c:
    li r0, 0x3
    b _ep_80295258
_ep_80295254:
    li r0, 0x4
_ep_80295258:
    cmpwi r0, 0x1
    bne _ep_80295264
    b _ep_8029532c
_ep_80295264:
    stfs f2, 0x10(r1)
    lis r0, 0x7f80
    lwz r4, 0x10(r1)
    rlwinm r3, r4, 0, 1, 8
    cmpw r3, r0
    beq _ep_8029528c
    bge _ep_802952c4
    cmpwi r3, 0x0
    beq _ep_802952a8
    b _ep_802952c4
_ep_8029528c:
    clrlwi r0, r4, 9
    cmpwi r0, 0x0
    beq _ep_802952a0
    li r0, 0x1
    b _ep_802952c8
_ep_802952a0:
    li r0, 0x2
    b _ep_802952c8
_ep_802952a8:
    clrlwi r0, r4, 9
    cmpwi r0, 0x0
    beq _ep_802952bc
    li r0, 0x5
    b _ep_802952c8
_ep_802952bc:
    li r0, 0x3
    b _ep_802952c8
_ep_802952c4:
    li r0, 0x4
_ep_802952c8:
    cmpwi r0, 0x3
    beq _ep_802952ec
    bge _ep_802952e0
    cmpwi r0, 0x1
    bge _ep_802952f4
    b _ep_80295328
_ep_802952e0:
    cmpwi r0, 0x6
    bge _ep_80295328
    b _ep_80295304
_ep_802952ec:
    lfs f1, lbl_803E7E58(r0)
    b _ep_8029532c
_ep_802952f4:
    lis r3, lbl_803DC648@ha
    addi r3, r3, lbl_803DC648@l
    lfs f1, 0x0(r3)
    b _ep_8029532c
_ep_80295304:
    lwz r0, 0x8(r1)
    clrrwi r0, r0, 31
    cmplwi r0, 0x0
    beq _ep_80295324
    lis r3, lbl_803DC64C@ha
    addi r3, r3, lbl_803DC64C@l
    lfs f1, 0x0(r3)
    b _ep_8029532c
_ep_80295324:
    b _ep_8029532c
_ep_80295328:
    lfs f1, lbl_803E7E50(r0)
_ep_8029532c:
    addi r1, r1, 0x90
    blr
}
