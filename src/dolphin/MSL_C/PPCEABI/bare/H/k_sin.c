/*
 * Target bytes at this split are not Sun's MSL __kernel_sin. This is a
 * game-side helper whose shape matches the other mislabeled-as-MSL funcs
 * in this area: takes a float, does threshold-based branching on |x| vs
 * a small constant, evaluates a short polynomial, and optionally mixes in
 * a call to __kernel_tan (which is itself game-side sqrt code from k_tan).
 * Asm-only to preserve the exact byte image.
 */

extern float __kernel_tan(float x);
extern float fn_80292DEC(float x);
void _savefpr_25(void);
void _restfpr_25(void);
void _savefpr_27(void);
void _restfpr_27(void);
void _savefpr_28(void);
void _restfpr_28(void);

extern const float lbl_803E79C0;
extern const float lbl_803E79C4;
extern const float lbl_803E79C8;
extern const float lbl_803E79CC;
extern const float lbl_803E79D0;
extern const float lbl_803E79D4;
extern const float lbl_803E79D8;
extern const float lbl_803E79E8;
extern const float lbl_803E79EC;
extern const float lbl_803E79F0;
extern const float lbl_803E79F4;
extern const float lbl_803E79F8;
extern const float lbl_803E79FC;
extern const float lbl_803E7A10;
extern const float lbl_803E7A14;
extern const float lbl_803E7A18;
extern const double lbl_803E79E0;
extern const double lbl_803E7A30;
extern const double lbl_803E7A38;
extern const double lbl_803E7A40;
extern const double lbl_803E7A48;
extern const double lbl_803E7A50;
extern const double lbl_803E7A58;
extern const double lbl_803E7A60;
extern const double lbl_803E7A68;
extern const double lbl_803E7A70;
extern const double lbl_803E7A78;
extern const double lbl_803E7A80;
extern const double lbl_803E7A88;
extern const double lbl_803E7A90;
extern const double lbl_803E7A98;
extern const double lbl_803E7AA0;
extern const double lbl_803E7AA8;
extern const double lbl_803E7AB0;

asm float __kernel_sin(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x38(r1)
    addi r11, r1, 0x38
    bl _savefpr_27
    fmr f30, f1
    fabs f29, f30
    lfs f0, lbl_803E79C0(r0)
    fcmpo cr0, f29, f0
    cror 2, 0, 2
    bne _ks_0
    fmuls f31, f30, f30
    lfs f1, lbl_803E79D4(r0)
    lfs f0, lbl_803E79D0(r0)
    fmadds f0, f1, f31, f0
    fmuls f1, f30, f0
    b _ks_end
_ks_0:
    lfs f1, lbl_803E79C0(r0)
    lfs f0, lbl_803E79C0(r0)
    fnmsubs f31, f1, f29, f0
    fmr f1, f31
    bl __kernel_tan
    fmr f27, f1
    lfs f1, lbl_803E79D4(r0)
    lfs f0, lbl_803E79D0(r0)
    fmadds f0, f1, f31, f0
    fmuls f28, f27, f0
    lfs f0, lbl_803E79C4(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _ks_1
    lfs f1, lbl_803E79CC(r0)
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f1, f1, f28, f0
    b _ks_end
_ks_1:
    lfs f1, lbl_803E79CC(r0)
    lfs f0, lbl_803E79C8(r0)
    fmsubs f1, f1, f28, f0
_ks_end:
    lwz r0, 0x3c(r1)
    addi r11, r1, 0x38
    bl _restfpr_27
    addi r1, r1, 0x38
    mtlr r0
    blr
}

asm float fn_80291FF4(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x38(r1)
    addi r11, r1, 0x38
    bl _savefpr_27
    fmr f30, f1
    fabs f29, f30
    lfs f0, lbl_803E79C0(r0)
    fcmpo cr0, f29, f0
    cror 2, 0, 2
    bne _f1ff4_0
    fmuls f31, f30, f30
    lfs f1, lbl_803E79D4(r0)
    lfs f0, lbl_803E79D0(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f1, f30, f1, f0
    b _f1ff4_end
_f1ff4_0:
    lfs f1, lbl_803E79C0(r0)
    lfs f0, lbl_803E79C0(r0)
    fnmsubs f31, f1, f29, f0
    fmr f1, f31
    bl __kernel_tan
    fmr f27, f1
    lfs f1, lbl_803E79D4(r0)
    lfs f0, lbl_803E79D0(r0)
    fmadds f0, f1, f31, f0
    fmuls f28, f27, f0
    lfs f0, lbl_803E79C4(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _f1ff4_1
    lfs f0, lbl_803E79CC(r0)
    fmuls f1, f0, f28
    b _f1ff4_end
_f1ff4_1:
    lfs f1, lbl_803E79CC(r0)
    lfs f0, lbl_803E79E8(r0)
    fnmsubs f1, f1, f28, f0
_f1ff4_end:
    lwz r0, 0x3c(r1)
    addi r11, r1, 0x38
    bl _restfpr_27
    addi r1, r1, 0x38
    mtlr r0
    blr
}

asm float fn_802920A4(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x38(r1)
    addi r11, r1, 0x38
    bl _savefpr_27
    fmr f30, f1
    fabs f29, f30
    lfs f0, lbl_803E79C0(r0)
    fcmpo cr0, f29, f0
    cror 2, 0, 2
    bne _f20a4_0
    fmuls f31, f30, f30
    lfs f1, lbl_803E79FC(r0)
    lfs f0, lbl_803E79F8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E79F4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79F0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79EC(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79D8(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f1, f30, f1, f0
    b _f20a4_end
_f20a4_0:
    lfs f1, lbl_803E79C0(r0)
    lfs f0, lbl_803E79C0(r0)
    fnmsubs f31, f1, f29, f0
    fmr f1, f31
    bl __kernel_tan
    fmr f27, f1
    lfs f1, lbl_803E79FC(r0)
    lfs f0, lbl_803E79F8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E79F4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79F0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79EC(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E79D8(r0)
    fmadds f0, f31, f1, f0
    fmuls f28, f27, f0
    lfs f0, lbl_803E79C4(r0)
    fcmpo cr0, f30, f0
    cror 2, 1, 2
    bne _f20a4_1
    lfs f0, lbl_803E79CC(r0)
    fmuls f1, f0, f28
    b _f20a4_end
_f20a4_1:
    lfs f1, lbl_803E79CC(r0)
    lfs f0, lbl_803E79E8(r0)
    fnmsubs f1, f1, f28, f0
_f20a4_end:
    lwz r0, 0x3c(r1)
    addi r11, r1, 0x38
    bl _restfpr_27
    addi r1, r1, 0x38
    mtlr r0
    blr
}

asm float fn_80292194(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_25
    fmr f29, f1
    fabs f28, f29
    lfs f0, lbl_803E79D8(r0)
    fcmpo cr0, f28, f0
    cror 2, 0, 2
    bne _f2194_0
    fmuls f31, f29, f29
    lfs f1, lbl_803E7A18(r0)
    lfs f0, lbl_803E7A14(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7A10(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f29, f0
    b _f2194_end
_f2194_0:
    fmr f1, f28
    bl fn_80292DEC
    fmr f30, f1
    fmuls f31, f30, f30
    lfs f1, lbl_803E7A18(r0)
    lfs f0, lbl_803E7A14(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7A10(r0)
    fmadds f27, f31, f1, f0
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f26, f30, f27, f0
    lfs f0, lbl_803E79C8(r0)
    fmsubs f25, f30, f27, f0
    lfs f0, lbl_803E79C4(r0)
    fcmpo cr0, f29, f0
    cror 2, 1, 2
    bne _f2194_1
    fmr f1, f26
    b _f2194_end
_f2194_1:
    fmr f1, f25
_f2194_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_25
    addi r1, r1, 0x48
    mtlr r0
    blr
}

asm float fn_80292248(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_28
    fabs f30, f1
    lfs f0, lbl_803E79D8(r0)
    fcmpo cr0, f30, f0
    cror 2, 0, 2
    bne _f2248_0
    fmuls f31, f1, f1
    lfd f2, lbl_803E7AA8(r0)
    lfd f0, lbl_803E7AA0(r0)
    fmadd f2, f2, f31, f0
    lfd f0, lbl_803E7A98(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A90(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A88(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A80(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A78(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A70(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A68(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A60(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A58(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A50(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A48(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A40(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A38(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A30(r0)
    fmadd f0, f31, f2, f0
    fmul f1, f1, f0
    frsp f1, f1
    b _f2248_end
_f2248_0:
    lfd f0, lbl_803E7AB0(r0)
    fdiv f29, f0, f30
    fmul f31, f29, f29
    lfd f2, lbl_803E7AA8(r0)
    lfd f0, lbl_803E7AA0(r0)
    fmadd f2, f2, f31, f0
    lfd f0, lbl_803E7A98(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A90(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A88(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A80(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A78(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A70(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A68(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A60(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A58(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A50(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A48(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A40(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A38(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E7A30(r0)
    fmadd f2, f31, f2, f0
    lfd f0, lbl_803E79E0(r0)
    fnmsub f28, f29, f2, f0
    frsp f28, f28
    lfs f0, lbl_803E79C4(r0)
    fcmpo cr0, f1, f0
    cror 2, 1, 2
    bne _f2248_1
    fmr f1, f28
    b _f2248_end
_f2248_1:
    fneg f1, f28
_f2248_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_28
    addi r1, r1, 0x30
    mtlr r0
    blr
}
