/*
 * Target bytes at this split are not Sun's MSL __kernel_sin. This is a
 * game-side helper whose shape matches the other mislabeled-as-MSL funcs
 * in this area: takes a float, does threshold-based branching on |x| vs
 * a small constant, evaluates a short polynomial, and optionally mixes in
 * a call to __kernel_tan (which is itself game-side sqrt code from k_tan).
 * Asm-only to preserve the exact byte image.
 */

extern float __kernel_tan(float x);
void _savefpr_27(void);
void _restfpr_27(void);

extern const float lbl_803E8658;
extern const float lbl_803E865C;
extern const float lbl_803E8660;
extern const float lbl_803E8664;
extern const float lbl_803E8668;
extern const float lbl_803E866C;
extern const float lbl_803E8680;

asm float __kernel_sin(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x38(r1)
    addi r11, r1, 0x38
    bl _savefpr_27
    fmr f30, f1
    fabs f29, f30
    lfs f0, lbl_803E8658(r0)
    fcmpo cr0, f29, f0
    cror 2, 0, 2
    bne _ks_0
    fmuls f31, f30, f30
    lfs f1, lbl_803E866C(r0)
    lfs f0, lbl_803E8668(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8660(r0)
    fnmsubs f1, f30, f1, f0
    b _ks_end
_ks_0:
    lfs f1, lbl_803E8658(r0)
    lfs f0, lbl_803E8658(r0)
    fnmsubs f31, f1, f29, f0
    fmr f1, f31
    bl __kernel_tan
    fmr f27, f1
    lfs f1, lbl_803E866C(r0)
    lfs f0, lbl_803E8668(r0)
    fmadds f0, f1, f31, f0
    fmuls f28, f27, f0
    lfs f0, lbl_803E865C(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _ks_1
    lfs f0, lbl_803E8664(r0)
    fmuls f1, f0, f28
    b _ks_end
_ks_1:
    lfs f1, lbl_803E8664(r0)
    lfs f0, lbl_803E8680(r0)
    fnmsubs f1, f1, f28, f0
_ks_end:
    lwz r0, 0x3c(r1)
    addi r11, r1, 0x38
    bl _restfpr_27
    addi r1, r1, 0x38
    mtlr r0
    blr
}
