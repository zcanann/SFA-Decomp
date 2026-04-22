/*
 * Target bytes at this split are not Sun's MSL __ieee754_sqrt. Game-side
 * helper with a long polynomial evaluation (19 fmadd terms via lbl_803E8760..
 * 803E87F8) gated on exponent extraction, then a second polynomial
 * (lbl_803E8808..lbl_803E8858) selected by fcmpu, with explicit
 * int-to-double magic-constant scaling and optional sign flip via fctiwz.
 * Asm-only to preserve the exact byte image.
 */

void _savefpr_28(void);
void _restfpr_28(void);

extern const float lbl_803E8750;
extern const double lbl_803E8758;
extern const double lbl_803E8760;
extern const double lbl_803E8768;
extern const double lbl_803E8770;
extern const double lbl_803E8778;
extern const double lbl_803E8780;
extern const double lbl_803E8788;
extern const double lbl_803E8790;
extern const double lbl_803E8798;
extern const double lbl_803E87A0;
extern const double lbl_803E87A8;
extern const double lbl_803E87B0;
extern const double lbl_803E87B8;
extern const double lbl_803E87C0;
extern const double lbl_803E87C8;
extern const double lbl_803E87D0;
extern const double lbl_803E87D8;
extern const double lbl_803E87E0;
extern const double lbl_803E87E8;
extern const double lbl_803E87F0;
extern const double lbl_803E87F8;
extern const double lbl_803E8800;
extern const double lbl_803E8808;
extern const double lbl_803E8810;
extern const double lbl_803E8818;
extern const double lbl_803E8820;
extern const double lbl_803E8828;
extern const double lbl_803E8830;
extern const double lbl_803E8838;
extern const double lbl_803E8840;
extern const double lbl_803E8848;
extern const double lbl_803E8850;
extern const double lbl_803E8858;
extern const float lbl_803E8860;
extern const double lbl_803E8868;

asm float __ieee754_sqrt(float x, float y) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x60(r1)
    addi r11, r1, 0x60
    bl _savefpr_28
    stmw r28, 0x30(r1)
    stfs f1, 0x8(r1)
    lfs f1, 0x8(r1)
    lfs f0, lbl_803E8750(r0)
    fcmpu cr0, f1, f0
    beq _sq_zero
    lwz r31, 0x8(r1)
    extrwi r3, r31, 8, 1
    subi r29, r3, 0x7f
    extsh r29, r29
    clrlwi r0, r31, 9
    oris r0, r0, 0x3f80
    stw r0, 0x10(r1)
    lfs f1, 0x10(r1)
    lfd f0, lbl_803E8758(r0)
    fsub f31, f1, f0
    lfd f1, lbl_803E87F8(r0)
    lfd f0, lbl_803E87F0(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E87E8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87E0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87D8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87D0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87C8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87C0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87B8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87B0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87A8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E87A0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8798(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8790(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8788(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8780(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8778(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8770(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8768(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8760(r0)
    fmadd f0, f31, f1, f0
    fmul f29, f31, f0
    lfd f1, lbl_803E8868(r0)
    xoris r0, r29, 0x8000
    stw r0, 0x2c(r1)
    lis r0, 0x4330
    stw r0, 0x28(r1)
    lfd f0, 0x28(r1)
    fsub f0, f0, f1
    fadd f0, f29, f0
    fmul f31, f2, f0
    fctiwz f0, f31
    stfd f0, 0x20(r1)
    lwz r30, 0x24(r1)
    lfd f1, lbl_803E8868(r0)
    xoris r0, r30, 0x8000
    stw r0, 0x1c(r1)
    lis r0, 0x4330
    stw r0, 0x18(r1)
    lfd f0, 0x18(r1)
    fsub f28, f0, f1
    fsub f30, f31, f28
    lfd f0, lbl_803E8800(r0)
    fcmpu cr0, f30, f0
    beq _sq_eq
    lfd f1, lbl_803E8858(r0)
    lfd f0, lbl_803E8850(r0)
    fmadd f1, f1, f30, f0
    lfd f0, lbl_803E8848(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8840(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8838(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8830(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8828(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8820(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8818(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8810(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E8808(r0)
    fmadd f0, f30, f1, f0
    frsp f0, f0
    b _sq_cont
_sq_eq:
    lfs f0, lbl_803E8860(r0)
_sq_cont:
    stfs f0, 0x14(r1)
    clrrwi. r0, r31, 31
    beq _sq_skip
    fctiwz f0, f2
    stfd f0, 0x18(r1)
    lwz r28, 0x1c(r1)
    clrlwi. r0, r28, 31
    beq _sq_skip
    lfs f0, 0x14(r1)
    fneg f0, f0
    stfs f0, 0x14(r1)
_sq_skip:
    lwz r3, 0x14(r1)
    slwi r0, r30, 23
    add r0, r3, r0
    stw r0, 0x14(r1)
    lfs f1, 0x14(r1)
    b _sq_done
_sq_zero:
    lfs f0, lbl_803E8750(r0)
    fcmpu cr0, f2, f0
    beq _sq_zero2
    lfs f1, lbl_803E8750(r0)
    b _sq_done
_sq_zero2:
    lfs f1, lbl_803E8860(r0)
_sq_done:
    lwz r0, 0x64(r1)
    addi r11, r1, 0x60
    bl _restfpr_28
    lmw r28, 0x30(r1)
    addi r1, r1, 0x60
    mtlr r0
    blr
}
