/*
 * Target bytes at this split are not Sun's MSL __kernel_cos. Game-side
 * 2-arg atan2-like helper: takes two floats (via r3=f1 slot, r4=f2 slot),
 * computes the ratio of the smaller to larger, evaluates a short polynomial,
 * then adjusts based on sign/quadrant extracted from the raw bits of the
 * inputs. Asm-only to preserve the exact byte image.
 */

void _savefpr_27(void);
void _restfpr_27(void);

extern const float lbl_803E8660;
extern const float lbl_803E8680;
extern const float lbl_803E86A0;
extern const float lbl_803E86A4;

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
    lfs f1, lbl_803E86A4(r0)
    lfs f0, lbl_803E86A0(r0)
    fmadds f0, f1, f27, f0
    fmuls f30, f31, f0
    b _kc_1
_kc_0:
    fdivs f31, f29, f28
    fmuls f27, f31, f31
    lfs f1, lbl_803E86A4(r0)
    lfs f0, lbl_803E86A0(r0)
    fmadds f1, f1, f27, f0
    lfs f0, lbl_803E8660(r0)
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
    lfs f0, lbl_803E8680(r0)
    fsubs f1, f0, f30
    b _kc_end
_kc_sub:
    lfs f0, lbl_803E8680(r0)
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
