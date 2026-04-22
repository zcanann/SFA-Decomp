/*
 * Target bytes at this split are not MSL's math_ppc wrappers. The symbol
 * table carves a continuous 180-byte body into five 0x24 slices (acosf /
 * fn_80292918 / fn_8029293C / fn_80292960 / powf) that don't make sense
 * as stand-alone functions - each is mid-flow, and only the first has a
 * prologue and only the last has an epilogue. Emitted as five asm bodies
 * whose concatenated bytes match target exactly after link.
 */

extern float fn_8029354C(float x);
void _savefpr_25(void);
void _restfpr_25(void);

extern const float lbl_803E865C;
extern const float lbl_803E8660;
extern const float lbl_803E8670;
extern const float lbl_803E86A8;
extern const float lbl_803E86AC;
extern const float lbl_803E86B0;

asm float acosf(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_25
    fmr f29, f1
    fabs f28, f29
    lfs f0, lbl_803E8670(r0)
    fcmpo cr0, f28, f0
}

void _mp1_loop(void);
asm void fn_80292918(void) {
    nofralloc
    cror 2, 0, 2
    entry _mp1_loop
    bne _mp1_loop
    fmuls f31, f29, f29
    lfs f1, lbl_803E86B0(r0)
    lfs f0, lbl_803E86AC(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E86A8(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f29, f0
}

asm void fn_8029293C(void) {
    nofralloc
    b fn_8029293C
    fmr f1, f28
    bl fn_8029354C
    fmr f30, f1
    fmuls f31, f30, f30
    lfs f1, lbl_803E86B0(r0)
    lfs f0, lbl_803E86AC(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E86A8(r0)
}

void _mp4_loop(void);
asm void fn_80292960(void) {
    nofralloc
    fmadds f27, f31, f1, f0
    lfs f0, lbl_803E8660(r0)
    fnmsubs f26, f30, f27, f0
    lfs f0, lbl_803E8660(r0)
    fmsubs f25, f30, f27, f0
    lfs f0, lbl_803E865C(r0)
    fcmpo cr0, f29, f0
    cror 2, 1, 2
    entry _mp4_loop
    bne _mp4_loop
}

asm float powf(float x, float y) {
    nofralloc
    fmr f1, f26
    b _mp5_end
    fmr f1, f25
_mp5_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_25
    addi r1, r1, 0x48
    mtlr r0
    blr
}
