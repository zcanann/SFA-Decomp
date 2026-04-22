/*
 * Target bytes at this split are not Sun's MSL acos(). Same pattern as k_sin:
 * branches on |x| vs threshold, evaluates a long polynomial, optionally mixes
 * with __kernel_tan (game-side sqrt). Asm-only to preserve byte image.
 */

extern float __kernel_tan(float x);
void _savefpr_27(void);
void _restfpr_27(void);

extern const float lbl_803E8658;
extern const float lbl_803E865C;
extern const float lbl_803E8660;
extern const float lbl_803E8664;
extern const float lbl_803E8670;
extern const float lbl_803E8680;
extern const float lbl_803E8684;
extern const float lbl_803E8688;
extern const float lbl_803E868C;
extern const float lbl_803E8690;
extern const float lbl_803E8694;

asm float acos(float x) {
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
    bne _sc_0
    fmuls f31, f30, f30
    lfs f1, lbl_803E8694(r0)
    lfs f0, lbl_803E8690(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E868C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8688(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8684(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8670(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8660(r0)
    fnmsubs f1, f30, f1, f0
    b _sc_end
_sc_0:
    lfs f1, lbl_803E8658(r0)
    lfs f0, lbl_803E8658(r0)
    fnmsubs f31, f1, f29, f0
    fmr f1, f31
    bl __kernel_tan
    fmr f27, f1
    lfs f1, lbl_803E8694(r0)
    lfs f0, lbl_803E8690(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E868C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8688(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8684(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8670(r0)
    fmadds f0, f31, f1, f0
    fmuls f28, f27, f0
    lfs f0, lbl_803E865C(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _sc_1
    lfs f0, lbl_803E8664(r0)
    fmuls f1, f0, f28
    b _sc_end
_sc_1:
    lfs f1, lbl_803E8664(r0)
    lfs f0, lbl_803E8680(r0)
    fnmsubs f1, f1, f28, f0
_sc_end:
    lwz r0, 0x3c(r1)
    addi r11, r1, 0x38
    bl _restfpr_27
    addi r1, r1, 0x38
    mtlr r0
    blr
}
