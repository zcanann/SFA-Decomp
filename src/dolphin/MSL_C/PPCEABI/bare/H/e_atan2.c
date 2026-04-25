/*
 * Target bytes at 0x80292B44..0x80292D3C absorbed into this TU. Five
 * helpers used by the s_sin/k_sin/k_cos atan2-style code:
 *   fn_80292B44 — pow-style mantissa/exponent extract + scale + multiply
 *   fn_80292C30 — orchestrator: calls fn_80292C9C, fn_80293954, fn_80292C74
 *   fn_80292C74 — Vec3 scale (multiplies 3 floats by f1, stores)
 *   fn_80292C9C — Vec3 dot product
 *   fn_80292CC4 — angle reduction helper (uses fn_80291CE4 + fn_80291CC8)
 * Asm-only to preserve the exact byte image.
 */

#include "dolphin.h"

extern float fn_80291CC8(short* p);
extern float fn_80291CE4(short* p, float x);
extern float fn_80291E08(short* p);
extern float fn_80293954(void);
asm void fn_80292C74(void* in, void* out, float scale);
asm float fn_80292C9C(void* v);
asm float fn_80292CC4(short* p, float x);

void _savefpr_30(void);
void _restfpr_30(void);

extern const float lbl_803E7AB8;
extern const float lbl_803E7BC8;
extern const float lbl_803E7BF4;
extern const float lbl_803E7BF8;

asm float fn_80292B44(float x, float y) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x40(r1)
    addi r11, r1, 0x40
    bl _savefpr_30
    stmw r30, 0x28(r1)
    stfs f1, 0x8(r1)
    fmr f31, f2
    lfs f1, 0x8(r1)
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f1, f0
    beq _b44_zero
    lwz r31, 0x8(r1)
    extrwi r3, r31, 8, 1
    subi r0, r3, 0x80
    sth r0, 0x10(r1)
    clrlwi r0, r31, 9
    oris r0, r0, 0x3f80
    stw r0, 0x14(r1)
    addi r3, r1, 0x10
    bl fn_80291E08
    fmr f30, f1
    lfs f0, lbl_803E7BF4(r0)
    fmuls f1, f0, f31
    lfs f0, 0x14(r1)
    fadds f0, f0, f30
    fmuls f0, f1, f0
    stfs f0, 0x14(r1)
    lfs f0, 0x14(r1)
    fctiwz f0, f0
    stfd f0, 0x20(r1)
    lwz r3, 0x24(r1)
    addis r0, r3, 0x3f80
    stw r0, 0x18(r1)
    clrrwi. r0, r31, 31
    beq _b44_skip
    fctiwz f0, f31
    stfd f0, 0x20(r1)
    lwz r30, 0x24(r1)
    clrlwi. r0, r30, 31
    beq _b44_skip
    lwz r0, 0x18(r1)
    xoris r0, r0, 0x8000
    stw r0, 0x18(r1)
_b44_skip:
    lfs f1, 0x18(r1)
    b _b44_end
_b44_zero:
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f31, f0
    beq _b44_zero2
    lfs f1, lbl_803E7AB8(r0)
    b _b44_end
_b44_zero2:
    lfs f1, lbl_803E7BC8(r0)
_b44_end:
    lwz r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _restfpr_30
    lmw r30, 0x28(r1)
    addi r1, r1, 0x40
    mtlr r0
    blr
}

asm void fn_80292C30(void* v_in, void* v_out) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x18(r1)
    stw r31, 0x14(r1)
    mr r31, r3
    stw r4, 0xc(r1)
    mr r3, r31
    bl fn_80292C9C
    bl fn_80293954
    mr r3, r31
    lwz r4, 0xc(r1)
    bl fn_80292C74
    lwz r0, 0x1c(r1)
    lwz r31, 0x14(r1)
    addi r1, r1, 0x18
    mtlr r0
    blr
}

asm void fn_80292C74(void* v_in, void* v_out, float s) {
    nofralloc
    lfs f0, 0x0(r3)
    fmuls f0, f0, f1
    stfs f0, 0x0(r4)
    lfs f0, 0x4(r3)
    fmuls f0, f0, f1
    stfs f0, 0x4(r4)
    lfs f0, 0x8(r3)
    fmuls f0, f0, f1
    stfs f0, 0x8(r4)
    blr
}

asm float fn_80292C9C(void* v) {
    nofralloc
    lfs f5, 0x8(r3)
    lfs f4, 0x8(r3)
    lfs f3, 0x0(r3)
    lfs f2, 0x0(r3)
    lfs f1, 0x4(r3)
    lfs f0, 0x4(r3)
    fmuls f0, f1, f0
    fmadds f0, f3, f2, f0
    fmadds f1, f5, f4, f0
    blr
}

asm float fn_80292CC4(short* p, float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    addi r11, r1, 0x28
    bl _savefpr_30
    stw r31, 0x14(r1)
    mr r31, r3
    stfs f1, 0xc(r1)
    lfs f1, lbl_803E7BF8(r0)
    lfs f0, 0xc(r1)
    fabs f0, f0
    fmuls f31, f1, f0
    fmr f1, f31
    mr r3, r31
    bl fn_80291CE4
    lhz r3, 0x0(r31)
    addi r0, r3, 0x1
    rlwinm r0, r0, 0, 16, 30
    sth r0, 0x0(r31)
    mr r3, r31
    bl fn_80291CC8
    fmr f30, f1
    fsubs f1, f31, f30
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}
