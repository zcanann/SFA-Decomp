/*
 * The target bytes in this TU are not Sun's __kernel_tan: they implement
 * sqrtf-style Newton-Raphson refinements of `frsqrte` (3/2/1 iterations)
 * followed by a fixed-point-angle sin/cos-like polynomial dispatcher.
 * The `__kernel_tan` / fn_* symbol names are retained to match the label
 * table; asm-only to preserve the exact byte image.
 */

extern float fn_80292568(short* x);
void _savefpr_30(void);
void _restfpr_30(void);

extern const float lbl_803E8908;
extern const float lbl_803E890C;
extern const float lbl_803E8910;
extern const float lbl_803E8918;
extern const float lbl_803E891C;
extern const float lbl_803E8920;
extern const float lbl_803E8924;
extern const float lbl_803E8928;

asm float __kernel_tan(float x) {
    nofralloc
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    stfd f30, 0x10(r1)
    lfs f0, lbl_803E8908(r0)
    fcmpu cr0, f0, f1
    beq _kt_0
    frsqrte f31, f1
    frsp f31, f31
    lfs f0, lbl_803E890C(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E8910(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f2, f30, f31
    lfs f0, lbl_803E8910(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f2, f30, f31
    lfs f0, lbl_803E8910(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f1, f31, f1
    b _kt_1
_kt_0:
    lfs f1, lbl_803E8908(r0)
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
    lfs f0, lbl_803E8908(r0)
    fcmpu cr0, f0, f1
    beq _f900_0
    frsqrte f31, f1
    frsp f31, f31
    lfs f0, lbl_803E890C(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E8910(r0)
    fnmsubs f0, f31, f2, f0
    fmuls f31, f31, f0
    fmuls f1, f31, f1
    b _f900_1
_f900_0:
    lfs f1, lbl_803E8908(r0)
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
    lfs f0, lbl_803E890C(r0)
    fmuls f30, f0, f1
    fmuls f2, f30, f31
    lfs f0, lbl_803E8910(r0)
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
    bl fn_80292568
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
    lfs f1, lbl_803E8928(r0)
    lfs f0, lbl_803E8924(r0)
    fmadds f0, f1, f31, f0
    fmuls f1, f30, f0
    b _f994_80
_f994_3c:
    lfs f1, lbl_803E8920(r0)
    lfs f0, lbl_803E891C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8918(r0)
    fmadds f1, f31, f1, f0
    b _f994_80
_f994_54:
    lfs f1, lbl_803E8928(r0)
    lfs f0, lbl_803E8924(r0)
    fmadds f0, f1, f31, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f994_80
_f994_6c:
    lfs f1, lbl_803E8920(r0)
    lfs f0, lbl_803E891C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8918(r0)
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
