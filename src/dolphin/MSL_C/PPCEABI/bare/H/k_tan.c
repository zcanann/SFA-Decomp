/*
 * The target bytes in this TU are not Sun's __kernel_tan: they implement
 * sqrtf-style Newton-Raphson refinements of `frsqrte` (3/2/1 iterations)
 * followed by a fixed-point-angle sin/cos-like polynomial dispatcher.
 * The `__kernel_tan` / fn_* symbol names are retained to match the label
 * table; asm-only to preserve the exact byte image.
 */

extern float fn_80291E08(short* x);
void _savefpr_30(void);
void _restfpr_30(void);

extern const float lbl_803E7C94;
extern const float lbl_803E7C98;
extern const float lbl_803E7C9C;
extern const float lbl_803E7CA0;
extern const float lbl_803E7CA4;
extern const float lbl_803E7CA8;
extern const float lbl_803E7CAC;
extern const float lbl_803E7C70;
extern const float lbl_803E7C74;
extern const float lbl_803E7C78;
extern const float lbl_803E7C80;
extern const float lbl_803E7C84;
extern const float lbl_803E7C88;
extern const float lbl_803E7C8C;
extern const float lbl_803E7C90;

asm float __kernel_tan(float x) {
    nofralloc
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    stfd f30, 0x10(r1)
    lfs f0, lbl_803E7C70(r0)
    fcmpu cr0, f0, f1
    beq _kt_0
    frsqrte f31, f1
    frsp f31, f31
    lfs f0, lbl_803E7C74(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E7C78(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f2, f30, f31
    lfs f0, lbl_803E7C78(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f2, f30, f31
    lfs f0, lbl_803E7C78(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f1, f31, f1
    b _kt_1
_kt_0:
    lfs f1, lbl_803E7C70(r0)
_kt_1:
    lfd f31, 0x18(r1)
    lfd f30, 0x10(r1)
    addi r1, r1, 0x20
    blr
}

asm float fn_80293900(float x) {
    nofralloc
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    stfd f30, 0x10(r1)
    lfs f0, lbl_803E7C70(r0)
    fcmpu cr0, f0, f1
    beq _f900_0
    frsqrte f31, f1
    frsp f31, f31
    lfs f0, lbl_803E7C74(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E7C78(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f1, f31, f1
    b _f900_1
_f900_0:
    lfs f1, lbl_803E7C70(r0)
_f900_1:
    lfd f31, 0x18(r1)
    lfd f30, 0x10(r1)
    addi r1, r1, 0x20
    blr
}

asm float fn_80293954(float x) {
    nofralloc
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    stfd f30, 0x10(r1)
    frsqrte f31, f1
    frsp f31, f31
    lfs f0, lbl_803E7C74(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E7C78(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmr f1, f31
    lfd f31, 0x18(r1)
    lfd f30, 0x10(r1)
    addi r1, r1, 0x20
    blr
}

asm float fn_80293994(int angle) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    addi r11, r1, 0x28
    bl _savefpr_30
    stw r31, 0x14(r1)
    mr r31, r3
    clrlslwi r0, r31, 16, 2
    extsh r0, r0
    sth r0, 0xa(r1)
    addi r3, r1, 0xa
    bl fn_80291E08
    fmr f30, f1
    fmuls f31, f30, f30
    rlwinm r0, r31, 0, 16, 18
    cmpwi r0, 0x6000
    beq _f994_54
    bge _f994_00
    cmpwi r0, 0x2000
    beq _f994_3c
    bge _f994_f4
    cmpwi r0, 0x0
    beq _f994_28
    b _f994_6c
_f994_f4:
    cmpwi r0, 0x4000
    beq _f994_3c
    b _f994_6c
_f994_00:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _f994_28
    bge _f994_6c
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f994_54
    b _f994_6c
_f994_28:
    lfs f1, lbl_803E7C90(r0)
    lfs f0, lbl_803E7C8C(r0)
    fmadds f0, f1, f31, f0
    fmuls f1, f30, f0
    b _f994_80
_f994_3c:
    lfs f1, lbl_803E7C88(r0)
    lfs f0, lbl_803E7C84(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C80(r0)
    fmadds f1, f31, f1, f0
    b _f994_80
_f994_54:
    lfs f1, lbl_803E7C90(r0)
    lfs f0, lbl_803E7C8C(r0)
    fmadds f0, f1, f31, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f994_80
_f994_6c:
    lfs f1, lbl_803E7C88(r0)
    lfs f0, lbl_803E7C84(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C80(r0)
    fnmadds f1, f31, f1, f0
_f994_80:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}

asm float fn_8029333C(int angle) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    addi r11, r1, 0x28
    bl _savefpr_30
    stw r31, 0x14(r1)
    mr r31, r3
    clrlslwi r0, r31, 16, 2
    extsh r0, r0
    sth r0, 0xa(r1)
    addi r3, r1, 0xa
    bl fn_80291E08
    fmr f30, f1
    fmuls f31, f30, f30
    rlwinm r0, r31, 0, 16, 18
    cmpwi r0, 0x6000
    beq _f33c_54
    bge _f33c_00
    cmpwi r0, 0x2000
    beq _f33c_3c
    bge _f33c_f4
    cmpwi r0, 0x0
    beq _f33c_28
    b _f33c_6c
_f33c_f4:
    cmpwi r0, 0x4000
    beq _f33c_3c
    b _f33c_6c
_f33c_00:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _f33c_28
    bge _f33c_6c
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f33c_54
    b _f33c_6c
_f33c_28:
    lfs f1, lbl_803E7C9C(r0)
    lfs f0, lbl_803E7C98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C94(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
    b _f33c_80
_f33c_3c:
    lfs f1, lbl_803E7CAC(r0)
    lfs f0, lbl_803E7CA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fmadds f1, f31, f1, f0
    b _f33c_80
_f33c_54:
    lfs f1, lbl_803E7C9C(r0)
    lfs f0, lbl_803E7C98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C94(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f33c_80
_f33c_6c:
    lfs f1, lbl_803E7CAC(r0)
    lfs f0, lbl_803E7CA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fnmadds f1, f31, f1, f0
_f33c_80:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}
