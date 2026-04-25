/*
 * Target bytes at this split are not Sun's MSL __ieee754_sqrt. Game-side
 * helper with a long polynomial evaluation (19 fmadd terms via lbl_803E7AC8..
 * 803E87F8) gated on exponent extraction, then a second polynomial
 * (lbl_803E7B70..lbl_803E7BC0) selected by fcmpu, with explicit
 * int-to-double magic-constant scaling and optional sign flip via fctiwz.
 * Asm-only to preserve the exact byte image.
 */

void _savefpr_28(void);
void _restfpr_28(void);
void _savefpr_29(void);
void _restfpr_29(void);
extern float fn_80291E08(short* x);
extern float fn_80291E24(short* x);

extern const float lbl_803E7BD8;
extern const float lbl_803E7BDC;
extern const float lbl_803E7BE0;
extern const float lbl_803E7BE4;
extern const float lbl_803E7BE8;
extern const float lbl_803E7BEC;
extern const float lbl_803E7BF0;

extern const float lbl_803E7AB8;
extern const double lbl_803E7AC0;
extern const double lbl_803E7AC8;
extern const double lbl_803E7AD0;
extern const double lbl_803E7AD8;
extern const double lbl_803E7AE0;
extern const double lbl_803E7AE8;
extern const double lbl_803E7AF0;
extern const double lbl_803E7AF8;
extern const double lbl_803E7B00;
extern const double lbl_803E7B08;
extern const double lbl_803E7B10;
extern const double lbl_803E7B18;
extern const double lbl_803E7B20;
extern const double lbl_803E7B28;
extern const double lbl_803E7B30;
extern const double lbl_803E7B38;
extern const double lbl_803E7B40;
extern const double lbl_803E7B48;
extern const double lbl_803E7B50;
extern const double lbl_803E7B58;
extern const double lbl_803E7B60;
extern const double lbl_803E7B68;
extern const double lbl_803E7B70;
extern const double lbl_803E7B78;
extern const double lbl_803E7B80;
extern const double lbl_803E7B88;
extern const double lbl_803E7B90;
extern const double lbl_803E7B98;
extern const double lbl_803E7BA0;
extern const double lbl_803E7BA8;
extern const double lbl_803E7BB0;
extern const double lbl_803E7BB8;
extern const double lbl_803E7BC0;
extern const float lbl_803E7BC8;
extern const double lbl_803E7BD0;

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
    lfs f0, lbl_803E7AB8(r0)
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
    lfd f0, lbl_803E7AC0(r0)
    fsub f31, f1, f0
    lfd f1, lbl_803E7B60(r0)
    lfd f0, lbl_803E7B58(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7B50(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B48(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B40(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B38(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B30(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B28(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B20(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B18(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B10(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B08(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7B00(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AF8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AE0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AD8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AD0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7AC8(r0)
    fmadd f0, f31, f1, f0
    fmul f29, f31, f0
    lfd f1, lbl_803E7BD0(r0)
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
    lfd f1, lbl_803E7BD0(r0)
    xoris r0, r30, 0x8000
    stw r0, 0x1c(r1)
    lis r0, 0x4330
    stw r0, 0x18(r1)
    lfd f0, 0x18(r1)
    fsub f28, f0, f1
    fsub f30, f31, f28
    lfd f0, lbl_803E7B68(r0)
    fcmpu cr0, f30, f0
    beq _sq_eq
    lfd f1, lbl_803E7BC0(r0)
    lfd f0, lbl_803E7BB8(r0)
    fmadd f1, f1, f30, f0
    lfd f0, lbl_803E7BB0(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7BA8(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7BA0(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B98(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B90(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B88(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B80(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B78(r0)
    fmadd f1, f30, f1, f0
    lfd f0, lbl_803E7B70(r0)
    fmadd f0, f30, f1, f0
    frsp f0, f0
    b _sq_cont
_sq_eq:
    lfs f0, lbl_803E7BC8(r0)
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
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f2, f0
    beq _sq_zero2
    lfs f1, lbl_803E7AB8(r0)
    b _sq_done
_sq_zero2:
    lfs f1, lbl_803E7BC8(r0)
_sq_done:
    lwz r0, 0x64(r1)
    addi r11, r1, 0x60
    bl _restfpr_28
    lmw r28, 0x30(r1)
    addi r1, r1, 0x60
    mtlr r0
    blr
}

asm float __ieee754_pow(float x, float y) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_29
    stmw r30, 0x28(r1)
    stfs f1, 0x8(r1)
    fmr f31, f2
    lfs f1, 0x8(r1)
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f1, f0
    beq _pw_zero
    lwz r31, 0x8(r1)
    extrwi r3, r31, 8, 1
    subi r0, r3, 0x7f
    sth r0, 0x12(r1)
    clrlwi r0, r31, 9
    oris r0, r0, 0x3f80
    stw r0, 0x14(r1)
    lfs f1, 0x14(r1)
    lfs f0, lbl_803E7BC8(r0)
    fsubs f0, f1, f0
    stfs f0, 0x14(r1)
    lfs f4, 0x14(r1)
    lfs f3, 0x14(r1)
    lfs f2, lbl_803E7BE4(r0)
    lfs f1, 0x14(r1)
    lfs f0, lbl_803E7BE0(r0)
    fmadds f1, f2, f1, f0
    lfs f0, lbl_803E7BDC(r0)
    fmadds f1, f3, f1, f0
    lfs f0, lbl_803E7BD8(r0)
    fmadds f0, f4, f1, f0
    stfs f0, 0x14(r1)
    addi r3, r1, 0x12
    bl fn_80291E08
    fmr f29, f1
    lfs f0, 0x14(r1)
    fadds f0, f0, f29
    fmuls f0, f31, f0
    stfs f0, 0x14(r1)
    lfs f1, 0x14(r1)
    addi r3, r1, 0x10
    bl fn_80291E24
    addi r3, r1, 0x10
    bl fn_80291E08
    fmr f30, f1
    lfs f0, 0x14(r1)
    fsubs f0, f0, f30
    stfs f0, 0x14(r1)
    lfs f1, 0x14(r1)
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f1, f0
    beq _pw_eq
    lfs f3, 0x14(r1)
    lfs f2, lbl_803E7BF0(r0)
    lfs f1, 0x14(r1)
    lfs f0, lbl_803E7BEC(r0)
    fmadds f1, f2, f1, f0
    lfs f0, lbl_803E7BE8(r0)
    fmadds f0, f3, f1, f0
    b _pw_cont
_pw_eq:
    lfs f0, lbl_803E7BC8(r0)
_pw_cont:
    stfs f0, 0x18(r1)
    clrrwi. r0, r31, 31
    beq _pw_skip
    fctiwz f0, f31
    stfd f0, 0x20(r1)
    lwz r30, 0x24(r1)
    clrlwi. r0, r30, 31
    beq _pw_skip
    lfs f0, 0x18(r1)
    fneg f0, f0
    stfs f0, 0x18(r1)
_pw_skip:
    lwz r3, 0x18(r1)
    lha r0, 0x10(r1)
    slwi r0, r0, 23
    add r0, r3, r0
    stw r0, 0x18(r1)
    lfs f1, 0x18(r1)
    b _pw_done
_pw_zero:
    lfs f0, lbl_803E7AB8(r0)
    fcmpu cr0, f31, f0
    beq _pw_zero2
    lfs f1, lbl_803E7AB8(r0)
    b _pw_done
_pw_zero2:
    lfs f1, lbl_803E7BC8(r0)
_pw_done:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_29
    lmw r30, 0x28(r1)
    addi r1, r1, 0x48
    mtlr r0
    blr
}
