/*
 * Target bytes at this split are not Sun's MSL __kernel_cos. Game-side
 * 2-arg atan2-like helper: takes two floats (via r3=f1 slot, r4=f2 slot),
 * computes the ratio of the smaller to larger, evaluates a short polynomial,
 * then adjusts based on sign/quadrant extracted from the raw bits of the
 * inputs. Asm-only to preserve the exact byte image.
 */

void _savefpr_27(void);
void _restfpr_27(void);

extern const float lbl_803E79C8;
extern const float lbl_803E79E8;
extern const float lbl_803E7A08;
extern const float lbl_803E7A0C;
extern const float lbl_803E7A1C;
extern const float lbl_803E7A20;
extern const float lbl_803E7A24;
extern const float lbl_803E7A28;
extern const double lbl_803E79E0;
extern const double lbl_803E7A00;
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

asm float __kernel_cos(float y, float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x40(r1)
    addi r11, r1, 0x40
    bl _savefpr_27
    stw r31, 0x14(r1)
    stfs f1, 0x8(r1)
    stfs f2, 0xc(r1)
    lfs f0, 0xc(r1)
    fabs f29, f0
    lfs f0, 0x8(r1)
    fabs f28, f0
    fcmpo cr0, f29, f28
    ble _kc_0
    fdivs f31, f28, f29
    fmuls f27, f31, f31
    lfs f1, lbl_803E7A0C(r0)
    lfs f0, lbl_803E7A08(r0)
    fmadds f0, f1, f27, f0
    fmuls f30, f31, f0
    b _kc_1
_kc_0:
    fdivs f31, f29, f28
    fmuls f27, f31, f31
    lfs f1, lbl_803E7A0C(r0)
    lfs f0, lbl_803E7A08(r0)
    fmadds f1, f1, f27, f0
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f30, f31, f1, f0
_kc_1:
    lwz r4, 0x8(r1)
    lwz r3, 0xc(r1)
    rlwinm r31, r3, 31, 1, 1
    rlwimi r31, r4, 0, 0, 0
    cmpwi r31, 0x0
    beq _kc_p
    bge _kc_q
    lis r3, 0x8000
    addi r3, r3, 0x1
    cmpw r31, r3
    bge _kc_sub
    b _kc_neg
_kc_q:
    lis r0, 0x4000
    cmpw r31, r0
    beq _kc_subpi
    b _kc_sub
_kc_p:
    fmr f1, f30
    b _kc_end
_kc_neg:
    fneg f1, f30
    b _kc_end
_kc_subpi:
    lfs f0, lbl_803E79E8(r0)
    fsubs f1, f0, f30
    b _kc_end
_kc_sub:
    lfs f0, lbl_803E79E8(r0)
    fsubs f1, f30, f0
_kc_end:
    lwz r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _restfpr_27
    lwz r31, 0x14(r1)
    addi r1, r1, 0x40
    mtlr r0
    blr
}

asm float fn_802924B4(float y, float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x40(r1)
    addi r11, r1, 0x40
    bl _savefpr_27
    stw r31, 0x14(r1)
    stfs f1, 0x8(r1)
    stfs f2, 0xc(r1)
    lfs f0, 0xc(r1)
    fabs f28, f0
    lfs f0, 0x8(r1)
    fabs f27, f0
    fcmpo cr0, f28, f27
    ble _f24b4_0
    fdivs f31, f27, f28
    fmuls f30, f31, f31
    lfs f1, lbl_803E7A28(r0)
    lfs f0, lbl_803E7A24(r0)
    fmadds f1, f1, f30, f0
    lfs f0, lbl_803E7A20(r0)
    fmadds f1, f30, f1, f0
    lfs f0, lbl_803E7A1C(r0)
    fmadds f0, f30, f1, f0
    fmuls f29, f31, f0
    b _f24b4_1
_f24b4_0:
    fdivs f31, f28, f27
    fmuls f30, f31, f31
    lfs f1, lbl_803E7A28(r0)
    lfs f0, lbl_803E7A24(r0)
    fmadds f1, f1, f30, f0
    lfs f0, lbl_803E7A20(r0)
    fmadds f1, f30, f1, f0
    lfs f0, lbl_803E7A1C(r0)
    fmadds f1, f30, f1, f0
    lfs f0, lbl_803E79C8(r0)
    fnmsubs f29, f31, f1, f0
_f24b4_1:
    lwz r4, 0x8(r1)
    lwz r3, 0xc(r1)
    rlwinm r31, r3, 31, 1, 1
    rlwimi r31, r4, 0, 0, 0
    cmpwi r31, 0
    beq _f24b4_p
    bge _f24b4_q
    lis r3, 0x8000
    addi r3, r3, 0x1
    cmpw r31, r3
    bge _f24b4_sub
    b _f24b4_neg
_f24b4_q:
    lis r0, 0x4000
    cmpw r31, r0
    beq _f24b4_subpi
    b _f24b4_sub
_f24b4_p:
    fmr f1, f29
    b _f24b4_end
_f24b4_neg:
    fneg f1, f29
    b _f24b4_end
_f24b4_subpi:
    lfs f0, lbl_803E79E8(r0)
    fsubs f1, f0, f29
    b _f24b4_end
_f24b4_sub:
    lfs f0, lbl_803E79E8(r0)
    fsubs f1, f29, f0
_f24b4_end:
    lwz r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _restfpr_27
    lwz r31, 0x14(r1)
    addi r1, r1, 0x40
    mtlr r0
    blr
}

asm float fn_802925C4(double y, double x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x40(r1)
    addi r11, r1, 0x40
    bl _savefpr_27
    stw r31, 0x14(r1)
    stfs f1, 0x8(r1)
    stfs f2, 0xc(r1)
    lfs f0, 0xc(r1)
    fabs f28, f0
    lfs f0, 0x8(r1)
    fabs f27, f0
    fcmpo cr0, f28, f27
    cror eq, gt, eq
    bne _f25c4_0
    fdivs f30, f27, f28
    fmul f31, f30, f30
    lfd f1, lbl_803E7AA8(r0)
    lfd f0, lbl_803E7AA0(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7A98(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A90(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A88(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A80(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A78(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A70(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A68(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A60(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A58(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A50(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A48(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A40(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A38(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A30(r0)
    fmadd f0, f31, f1, f0
    fmul f29, f30, f0
    b _f25c4_1
_f25c4_0:
    fdivs f30, f28, f27
    fmul f31, f30, f30
    lfd f1, lbl_803E7AA8(r0)
    lfd f0, lbl_803E7AA0(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7A98(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A90(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A88(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A80(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A78(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A70(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A68(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A60(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A58(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A50(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A48(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A40(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A38(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7A30(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E79E0(r0)
    fnmsub f29, f30, f1, f0
_f25c4_1:
    lwz r4, 0x8(r1)
    lwz r3, 0xc(r1)
    rlwinm r31, r3, 31, 1, 1
    rlwimi r31, r4, 0, 0, 0
    cmpwi r31, 0
    beq _f25c4_p
    bge _f25c4_q
    lis r3, 0x8000
    addi r3, r3, 0x1
    cmpw r31, r3
    bge _f25c4_sub
    b _f25c4_neg
_f25c4_q:
    lis r0, 0x4000
    cmpw r31, r0
    beq _f25c4_subpi
    b _f25c4_sub
_f25c4_p:
    frsp f1, f29
    b _f25c4_end
_f25c4_neg:
    fneg f1, f29
    frsp f1, f1
    b _f25c4_end
_f25c4_subpi:
    lfd f0, lbl_803E7A00(r0)
    fsub f1, f0, f29
    frsp f1, f1
    b _f25c4_end
_f25c4_sub:
    lfd f0, lbl_803E7A00(r0)
    fsub f1, f29, f0
    frsp f1, f1
_f25c4_end:
    lwz r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _restfpr_27
    lwz r31, 0x14(r1)
    addi r1, r1, 0x40
    mtlr r0
    blr
}
