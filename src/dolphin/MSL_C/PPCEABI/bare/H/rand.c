#include "dolphin.h"

// rand.c from Runtime library

extern u32 lbl_803DE410;

extern float fn_80291E08(short* p);
void _savefpr_28(void);
void _restfpr_28(void);

extern const float lbl_803E7C18;
extern const float lbl_803E7C20;
extern const float lbl_803E7C24;
extern const float lbl_803E7C28;
extern const float lbl_803E7C2C;
extern const float lbl_803E7C30;
extern const float lbl_803E7C34;
extern const float lbl_803E7C38;
extern const float lbl_803E7C3C;
extern const float lbl_803E7C40;
extern const float lbl_803E7C44;
extern const float lbl_803E7C48;
extern const float lbl_803E7C4C;
extern const float lbl_803E7C50;
extern const float lbl_803E7C54;
extern const float lbl_803E7C58;
extern const float lbl_803E7C5C;
extern const float lbl_803E7C60;
extern const float lbl_803E7C64;
extern const float lbl_803E7C68;
extern const float lbl_803E7C6C;

asm u32 rand(void) {
    nofralloc
    lwz r0, lbl_803DE410
    lis r3, 25
    addi r3, r3, 0x660D
    mullw r3, r0, r3
    addis r3, r3, 0x3C6F
    addi r0, r3, -3233
    stw r0, lbl_803DE410
    lwz r3, lbl_803DE410
    blr
}

void srand(u32 seed) {
    lbl_803DE410 = seed;
}

asm float fn_80292DEC(float x) {
    nofralloc
    stwu r1, -0x18(r1)
    stfd f31, 0x10(r1)
    fres f31, f1
    lfs f0, lbl_803E7C18(r0)
    fnmsubs f0, f1, f31, f0
    fmuls f31, f31, f0
    lfs f0, lbl_803E7C18(r0)
    fnmsubs f0, f1, f31, f0
    fmuls f31, f31, f0
    fmr f1, f31
    lfd f31, 0x10(r1)
    addi r1, r1, 0x18
    blr
}

asm void fn_80292E20(int q, float* sin_out, float* cos_out) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_28
    stmw r29, 0x1c(r1)
    addi r29, r3, 0
    addi r30, r4, 0
    addi r31, r5, 0
    clrlslwi r0, r29, 16, 2
    extsh r0, r0
    sth r0, 0x14(r1)
    addi r3, r1, 0x14
    bl fn_80291E08
    fmr f29, f1
    fmuls f28, f29, f29
    lfs f1, lbl_803E7C24(r0)
    lfs f0, lbl_803E7C20(r0)
    fmadds f0, f1, f28, f0
    fmuls f31, f29, f0
    lfs f1, lbl_803E7C30(r0)
    lfs f0, lbl_803E7C2C(r0)
    fmadds f1, f1, f28, f0
    lfs f0, lbl_803E7C28(r0)
    fmadds f30, f28, f1, f0
    clrlwi r3, r29, 16
    addi r0, r3, 0x2000
    rlwinm r0, r0, 0, 16, 17
    cmpwi r0, 0x4000
    beq _f2e20_q1
    bge _f2e20_ge
    cmpwi r0, 0x0
    beq _f2e20_q0
    b _f2e20_q3
_f2e20_ge:
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f2e20_q2
    b _f2e20_q3
_f2e20_q0:
    stfs f31, 0(r30)
    stfs f30, 0(r31)
    b _f2e20_end
_f2e20_q1:
    stfs f30, 0(r30)
    fneg f0, f31
    stfs f0, 0(r31)
    b _f2e20_end
_f2e20_q2:
    fneg f0, f31
    stfs f0, 0(r30)
    fneg f0, f30
    stfs f0, 0(r31)
    b _f2e20_end
_f2e20_q3:
    fneg f0, f30
    stfs f0, 0(r30)
    stfs f31, 0(r31)
_f2e20_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_28
    lmw r29, 0x1c(r1)
    addi r1, r1, 0x48
    mtlr r0
    blr
}

asm void fn_80292F14(int q, float* sin_out, float* cos_out) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_28
    stmw r29, 0x1c(r1)
    addi r29, r3, 0
    addi r30, r4, 0
    addi r31, r5, 0
    clrlslwi r0, r29, 16, 2
    extsh r0, r0
    sth r0, 0x14(r1)
    addi r3, r1, 0x14
    bl fn_80291E08
    fmr f28, f1
    fmuls f31, f28, f28
    lfs f1, lbl_803E7C3C(r0)
    lfs f0, lbl_803E7C38(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C34(r0)
    fmadds f0, f31, f1, f0
    fmuls f30, f28, f0
    lfs f1, lbl_803E7C4C(r0)
    lfs f0, lbl_803E7C48(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C44(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7C40(r0)
    fmadds f29, f31, f1, f0
    clrlwi r3, r29, 16
    addi r0, r3, 0x2000
    rlwinm r0, r0, 0, 16, 17
    cmpwi r0, 0x4000
    beq _f2f14_q1
    bge _f2f14_ge
    cmpwi r0, 0x0
    beq _f2f14_q0
    b _f2f14_q3
_f2f14_ge:
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f2f14_q2
    b _f2f14_q3
_f2f14_q0:
    stfs f30, 0(r30)
    stfs f29, 0(r31)
    b _f2f14_end
_f2f14_q1:
    stfs f29, 0(r30)
    fneg f0, f30
    stfs f0, 0(r31)
    b _f2f14_end
_f2f14_q2:
    fneg f0, f30
    stfs f0, 0(r30)
    fneg f0, f29
    stfs f0, 0(r31)
    b _f2f14_end
_f2f14_q3:
    fneg f0, f29
    stfs f0, 0(r30)
    stfs f30, 0(r31)
_f2f14_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_28
    lmw r29, 0x1c(r1)
    addi r1, r1, 0x48
    mtlr r0
    blr
}

asm void fn_80293018(int q, float* sin_out, float* cos_out) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_28
    stmw r29, 0x1c(r1)
    addi r29, r3, 0
    addi r30, r4, 0
    addi r31, r5, 0
    clrlslwi r0, r29, 16, 2
    extsh r0, r0
    sth r0, 0x14(r1)
    addi r3, r1, 0x14
    bl fn_80291E08
    fmr f28, f1
    fmuls f31, f28, f28
    lfs f1, lbl_803E7C5C(r0)
    lfs f0, lbl_803E7C58(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C54(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7C50(r0)
    fmadds f0, f31, f1, f0
    fmuls f30, f28, f0
    lfs f1, lbl_803E7C6C(r0)
    lfs f0, lbl_803E7C68(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C64(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7C60(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7C40(r0)
    fmadds f29, f31, f1, f0
    clrlwi r3, r29, 16
    addi r0, r3, 0x2000
    rlwinm r0, r0, 0, 16, 17
    cmpwi r0, 0x4000
    beq _f3018_q1
    bge _f3018_ge
    cmpwi r0, 0x0
    beq _f3018_q0
    b _f3018_q3
_f3018_ge:
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f3018_q2
    b _f3018_q3
_f3018_q0:
    stfs f30, 0(r30)
    stfs f29, 0(r31)
    b _f3018_end
_f3018_q1:
    stfs f29, 0(r30)
    fneg f0, f30
    stfs f0, 0(r31)
    b _f3018_end
_f3018_q2:
    fneg f0, f30
    stfs f0, 0(r30)
    fneg f0, f29
    stfs f0, 0(r31)
    b _f3018_end
_f3018_q3:
    fneg f0, f29
    stfs f0, 0(r30)
    stfs f30, 0(r31)
_f3018_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_28
    lmw r29, 0x1c(r1)
    addi r1, r1, 0x48
    mtlr r0
    blr
}
