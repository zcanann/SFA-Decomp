/*
 * The target bytes at this split are not Sun's IEEE-754 remainder of x/(pi/2)
 * implementation. They're three fixed-point-angle sin/cos/tan-like polynomial
 * dispatchers (same pattern as k_tan.c's fn_80293994): switch on the top 3
 * bits of an int angle (0x0/0x2000/0x4000/0x6000/0x8000/0xE000), call
 * fn_80291E08 to convert the short to a float, then evaluate a quadrant-
 * specific polynomial. __ieee754_rem_pio2/fn_80293D0C/fn_80293EAC differ only
 * in precision (float vs double) and coefficient set. Asm-only to preserve
 * the exact byte image.
 */

extern float fn_80291E08(short* x);
extern float fn_80291E08(short* p);
extern float fn_80292CC4(short* p, float x);
void _savefpr_27(void);
void _savefpr_29(void);
void _savefpr_30(void);
void _restfpr_27(void);
void _restfpr_29(void);
void _restfpr_30(void);

extern const float lbl_803E7CA0;
extern const float lbl_803E7CB0;
extern const float lbl_803E7CB4;
extern const float lbl_803E7CB8;
extern const float lbl_803E7CBC;
extern const float lbl_803E7CC0;
extern const float lbl_803E7CC4;
extern const float lbl_803E7CC8;
extern const float lbl_803E7CCC;
extern const double lbl_803E7CD0;
extern const double lbl_803E7CD8;
extern const double lbl_803E7CE0;
extern const double lbl_803E7CE8;
extern const double lbl_803E7CF0;
extern const double lbl_803E7CF8;
extern const double lbl_803E7D00;
extern const double lbl_803E7D08;
extern const double lbl_803E7D10;
extern const double lbl_803E7D18;
extern const double lbl_803E7D20;
extern const double lbl_803E7D28;
extern const double lbl_803E7D30;
extern const double lbl_803E7D38;
extern const float lbl_803E7C80;
extern const float lbl_803E7C84;
extern const float lbl_803E7C88;
extern const float lbl_803E7C8C;
extern const float lbl_803E7C90;

asm float __ieee754_rem_pio2(int angle) {
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
    beq _erp1_a
    bge _erp1_h
    cmpwi r0, 0x2000
    beq _erp1_b
    bge _erp1_g
    cmpwi r0, 0x0
    beq _erp1_c
    b _erp1_d
_erp1_g:
    cmpwi r0, 0x4000
    beq _erp1_b
    b _erp1_d
_erp1_h:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _erp1_c
    bge _erp1_d
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _erp1_a
    b _erp1_d
_erp1_c:
    lfs f1, lbl_803E7CBC(r0)
    lfs f0, lbl_803E7CB8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CB4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CB0(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
    b _erp1_end
_erp1_b:
    lfs f1, lbl_803E7CCC(r0)
    lfs f0, lbl_803E7CC8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CC4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CC0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fmadds f1, f31, f1, f0
    b _erp1_end
_erp1_a:
    lfs f1, lbl_803E7CBC(r0)
    lfs f0, lbl_803E7CB8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CB4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CB0(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _erp1_end
_erp1_d:
    lfs f1, lbl_803E7CCC(r0)
    lfs f0, lbl_803E7CC8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CC4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CC0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fnmadds f1, f31, f1, f0
_erp1_end:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}

asm float fn_80293D0C(int angle) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_29
    stw r31, 0x14(r1)
    mr r31, r3
    clrlslwi r0, r31, 16, 2
    extsh r0, r0
    sth r0, 0xa(r1)
    addi r3, r1, 0xa
    bl fn_80291E08
    fmr f29, f1
    lfd f0, lbl_803E7CD0(r0)
    fmul f30, f0, f29
    fmul f31, f30, f30
    rlwinm r0, r31, 0, 16, 18
    cmpwi r0, 0x6000
    beq _erp2_a
    bge _erp2_h
    cmpwi r0, 0x2000
    beq _erp2_b
    bge _erp2_g
    cmpwi r0, 0x0
    beq _erp2_c
    b _erp2_d
_erp2_g:
    cmpwi r0, 0x4000
    beq _erp2_b
    b _erp2_d
_erp2_h:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _erp2_c
    bge _erp2_d
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _erp2_a
    b _erp2_d
_erp2_c:
    lfd f1, lbl_803E7D00(r0)
    lfd f0, lbl_803E7CF8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7CF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CD8(r0)
    fmadd f0, f31, f1, f0
    fmul f1, f30, f0
    frsp f1, f1
    b _erp2_end
_erp2_b:
    lfd f1, lbl_803E7D38(r0)
    lfd f0, lbl_803E7D30(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7D28(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D20(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D18(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D10(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D08(r0)
    fmadd f1, f31, f1, f0
    frsp f1, f1
    b _erp2_end
_erp2_a:
    lfd f1, lbl_803E7D00(r0)
    lfd f0, lbl_803E7CF8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7CF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CD8(r0)
    fmadd f0, f31, f1, f0
    fmul f0, f30, f0
    fneg f1, f0
    frsp f1, f1
    b _erp2_end
_erp2_d:
    lfd f1, lbl_803E7D38(r0)
    lfd f0, lbl_803E7D30(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7D28(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D20(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D18(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D10(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D08(r0)
    fnmadd f1, f31, f1, f0
    frsp f1, f1
_erp2_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_29
    lwz r31, 0x14(r1)
    addi r1, r1, 0x30
    mtlr r0
    blr
}

asm float fn_80293EAC(int angle) {
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
    beq _erp3_a
    bge _erp3_h
    cmpwi r0, 0x2000
    beq _erp3_b
    bge _erp3_g
    cmpwi r0, 0x0
    beq _erp3_c
    b _erp3_d
_erp3_g:
    cmpwi r0, 0x4000
    beq _erp3_b
    b _erp3_d
_erp3_h:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _erp3_c
    bge _erp3_d
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _erp3_a
    b _erp3_d
_erp3_c:
    lfs f1, lbl_803E7C88(r0)
    lfs f0, lbl_803E7C84(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C80(r0)
    fmadds f1, f31, f1, f0
    b _erp3_end
_erp3_b:
    lfs f1, lbl_803E7C90(r0)
    lfs f0, lbl_803E7C8C(r0)
    fmadds f0, f1, f31, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _erp3_end
_erp3_a:
    lfs f1, lbl_803E7C88(r0)
    lfs f0, lbl_803E7C84(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C80(r0)
    fnmadds f1, f31, f1, f0
    b _erp3_end
_erp3_d:
    lfs f1, lbl_803E7C90(r0)
    lfs f0, lbl_803E7C8C(r0)
    fmadds f0, f1, f31, f0
    fmuls f1, f30, f0
_erp3_end:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}

extern const float lbl_803E7C94;
extern const float lbl_803E7C98;
extern const float lbl_803E7C9C;
extern const float lbl_803E7CA0;
extern const float lbl_803E7CA4;
extern const float lbl_803E7CA8;
extern const float lbl_803E7CAC;
extern const float lbl_803E7CB0;
extern const float lbl_803E7CB4;
extern const float lbl_803E7CB8;
extern const float lbl_803E7CBC;
extern const float lbl_803E7CC0;
extern const float lbl_803E7CC4;
extern const float lbl_803E7CC8;
extern const float lbl_803E7CCC;
extern const double lbl_803E7CD0;
extern const double lbl_803E7CD8;
extern const double lbl_803E7CE0;
extern const double lbl_803E7CE8;
extern const double lbl_803E7CF0;
extern const double lbl_803E7CF8;
extern const double lbl_803E7D00;
extern const double lbl_803E7D08;
extern const double lbl_803E7D10;
extern const double lbl_803E7D18;
extern const double lbl_803E7D20;
extern const double lbl_803E7D28;
extern const double lbl_803E7D30;
extern const double lbl_803E7D38;
extern const float lbl_803E7D40;
extern const float lbl_803E7D44;
extern const float lbl_803E7D48;
extern const float lbl_803E7D4C;
extern const float lbl_803E7D50;
extern const float lbl_803E7D54;
extern const float lbl_803E7D58;
extern const float lbl_803E7D5C;
extern const float lbl_803E7D60;
extern const float lbl_803E7D64;
extern const float lbl_803E7D68;
extern const float lbl_803E7D6C;
extern const float lbl_803E7D70;
extern const float lbl_803E7D74;
extern const float lbl_803E7D78;
extern const float lbl_803E7D7C;
extern const float lbl_803E7D80;
extern const float lbl_803E7D84;
extern const float lbl_803E7D88;
extern const float lbl_803E7D8C;
extern const float lbl_803E7D90;
extern const float lbl_803E7D94;
extern const float lbl_803E7D98;
extern const float lbl_803E7D9C;
extern const float lbl_803E7DA0;
extern const float lbl_803E7DA4;
extern const float lbl_803E7DA8;
extern const float lbl_803E7DAC;

asm float fn_80293854(int angle) {
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
    beq _f3854_q3
    bge _f3854_high
    cmpwi r0, 0x2000
    beq _f3854_q1
    bge _f3854_lo
    cmpwi r0, 0
    beq _f3854_q0
    b _f3854_q3b
_f3854_lo:
    cmpwi r0, 0x4000
    beq _f3854_q1
    b _f3854_q3b
_f3854_high:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _f3854_q0
    bge _f3854_q3b
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f3854_q3
    b _f3854_q3b
_f3854_q0:
    lfs f1, lbl_803E7CAC(r0)
    lfs f0, lbl_803E7CA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fmadds f1, f31, f1, f0
    b _f3854_end
_f3854_q1:
    lfs f1, lbl_803E7C9C(r0)
    lfs f0, lbl_803E7C98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C94(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f3854_end
_f3854_q3:
    lfs f1, lbl_803E7CAC(r0)
    lfs f0, lbl_803E7CA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fnmadds f1, f31, f1, f0
    b _f3854_end
_f3854_q3b:
    lfs f1, lbl_803E7C9C(r0)
    lfs f0, lbl_803E7C98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7C94(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
_f3854_end:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}

asm float fn_8029397C(int angle) {
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
    beq _f397c_q3
    bge _f397c_high
    cmpwi r0, 0x2000
    beq _f397c_q1
    bge _f397c_lo
    cmpwi r0, 0
    beq _f397c_q0
    b _f397c_q3b
_f397c_lo:
    cmpwi r0, 0x4000
    beq _f397c_q1
    b _f397c_q3b
_f397c_high:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _f397c_q0
    bge _f397c_q3b
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f397c_q3
    b _f397c_q3b
_f397c_q0:
    lfs f1, lbl_803E7CCC(r0)
    lfs f0, lbl_803E7CC8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CC4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CC0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fmadds f1, f31, f1, f0
    b _f397c_end
_f397c_q1:
    lfs f1, lbl_803E7CBC(r0)
    lfs f0, lbl_803E7CB8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CB4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CB0(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f397c_end
_f397c_q3:
    lfs f1, lbl_803E7CCC(r0)
    lfs f0, lbl_803E7CC8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CC4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CC0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CA0(r0)
    fnmadds f1, f31, f1, f0
    b _f397c_end
_f397c_q3b:
    lfs f1, lbl_803E7CBC(r0)
    lfs f0, lbl_803E7CB8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7CB4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7CB0(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
_f397c_end:
    lwz r0, 0x2c(r1)
    addi r11, r1, 0x28
    bl _restfpr_30
    lwz r31, 0x14(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}

asm float fn_80293AC4(int angle) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_29
    stw r31, 0x14(r1)
    mr r31, r3
    clrlslwi r0, r31, 16, 2
    extsh r0, r0
    sth r0, 0xa(r1)
    addi r3, r1, 0xa
    bl fn_80291E08
    fmr f29, f1
    lfd f0, lbl_803E7CD0(r0)
    fmul f30, f0, f29
    fmul f31, f30, f30
    rlwinm r0, r31, 0, 16, 18
    cmpwi r0, 0x6000
    beq _f3ac4_q3
    bge _f3ac4_high
    cmpwi r0, 0x2000
    beq _f3ac4_q1
    bge _f3ac4_lo
    cmpwi r0, 0
    beq _f3ac4_q0
    b _f3ac4_q3b
_f3ac4_lo:
    cmpwi r0, 0x4000
    beq _f3ac4_q1
    b _f3ac4_q3b
_f3ac4_high:
    lis r3, 0x1
    subi r3, r3, 0x2000
    cmpw r0, r3
    beq _f3ac4_q0
    bge _f3ac4_q3b
    lis r3, 0x1
    addi r3, r3, -0x8000
    cmpw r0, r3
    beq _f3ac4_q3
    b _f3ac4_q3b
_f3ac4_q0:
    lfd f1, lbl_803E7D38(r0)
    lfd f0, lbl_803E7D30(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7D28(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D20(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D18(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D10(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D08(r0)
    fmadd f1, f31, f1, f0
    frsp f1, f1
    b _f3ac4_end
_f3ac4_q1:
    lfd f1, lbl_803E7D00(r0)
    lfd f0, lbl_803E7CF8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7CF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CD8(r0)
    fmadd f0, f31, f1, f0
    fmul f0, f30, f0
    fneg f1, f0
    frsp f1, f1
    b _f3ac4_end
_f3ac4_q3:
    lfd f1, lbl_803E7D38(r0)
    lfd f0, lbl_803E7D30(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7D28(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D20(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D18(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D10(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7D08(r0)
    fnmadd f1, f31, f1, f0
    frsp f1, f1
    b _f3ac4_end
_f3ac4_q3b:
    lfd f1, lbl_803E7D00(r0)
    lfd f0, lbl_803E7CF8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7CF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CE0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7CD8(r0)
    fmadd f0, f31, f1, f0
    fmul f1, f30, f0
    frsp f1, f1
_f3ac4_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_29
    lwz r31, 0x14(r1)
    addi r1, r1, 0x30
    mtlr r0
    blr
}

asm void fn_80293C64(float x, float* sin_out, float* cos_out) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x48(r1)
    addi r11, r1, 0x48
    bl _savefpr_27
    stmw r30, 0x18(r1)
    fmr f28, f1
    addi r30, r3, 0
    addi r31, r4, 0
    addi r3, r1, 0x14
    fmr f1, f28
    bl fn_80292CC4
    fmr f27, f1
    fmuls f29, f27, f27
    lfs f1, lbl_803E7D4C(r0)
    lfs f0, lbl_803E7D48(r0)
    fmadds f1, f1, f29, f0
    lfs f0, lbl_803E7D44(r0)
    fmadds f0, f29, f1, f0
    fmuls f31, f27, f0
    lfs f1, lbl_803E7D5C(r0)
    lfs f0, lbl_803E7D58(r0)
    fmadds f1, f1, f29, f0
    lfs f0, lbl_803E7D54(r0)
    fmadds f1, f29, f1, f0
    lfs f0, lbl_803E7D50(r0)
    fmadds f30, f29, f1, f0
    lhz r0, 0x14(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f3c64_q2
    bge _f3c64_ge
    cmpwi r0, 0
    beq _f3c64_q0
    b _f3c64_q3
_f3c64_ge:
    cmpwi r0, 0x4
    beq _f3c64_q4
    b _f3c64_q3
_f3c64_q0:
    lfs f0, lbl_803E7D40(r0)
    fcmpo cr0, f28, f0
    cror 2, 1, 2
    bne _f3c64_q0_neg
    b _f3c64_q0_pos
_f3c64_q0_neg:
    fneg f31, f31
_f3c64_q0_pos:
    stfs f31, 0(r30)
    stfs f30, 0(r31)
    b _f3c64_end
_f3c64_q2:
    lfs f0, lbl_803E7D40(r0)
    fcmpo cr0, f28, f0
    cror 2, 1, 2
    bne _f3c64_q2_neg
    b _f3c64_q2_pos
_f3c64_q2_neg:
    fneg f30, f30
_f3c64_q2_pos:
    stfs f30, 0(r30)
    fneg f0, f31
    stfs f0, 0(r31)
    b _f3c64_end
_f3c64_q4:
    lfs f0, lbl_803E7D40(r0)
    fcmpo cr0, f28, f0
    cror 2, 1, 2
    bne _f3c64_q4_skip
    fneg f31, f31
_f3c64_q4_skip:
    stfs f31, 0(r30)
    fneg f0, f30
    stfs f0, 0(r31)
    b _f3c64_end
_f3c64_q3:
    lfs f0, lbl_803E7D40(r0)
    fcmpo cr0, f28, f0
    cror 2, 1, 2
    bne _f3c64_q3_skip
    fneg f30, f30
_f3c64_q3_skip:
    stfs f30, 0(r30)
    stfs f31, 0(r31)
_f3c64_end:
    lwz r0, 0x4c(r1)
    addi r11, r1, 0x48
    bl _restfpr_27
    lmw r30, 0x18(r1)
    addi r1, r1, 0x48
    mtlr r0
    blr
}

asm float fn_80293DA4(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    addi r11, r1, 0x20
    bl _savefpr_30
    stfs f1, 0x8(r1)
    addi r3, r1, 0xc
    lfs f1, 0x8(r1)
    bl fn_80292CC4
    fmr f30, f1
    lhz r4, 0xc(r1)
    lwz r3, 0x8(r1)
    rlwinm r0, r3, 3, 29, 29
    add r0, r4, r0
    sth r0, 0xc(r1)
    fmuls f31, f30, f30
    lhz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f3da4_q2
    bge _f3da4_ge
    cmpwi r0, 0
    beq _f3da4_q0
    b _f3da4_q3
_f3da4_ge:
    cmpwi r0, 0x4
    beq _f3da4_q4
    b _f3da4_q3
_f3da4_q0:
    lfs f1, lbl_803E7D64(r0)
    lfs f0, lbl_803E7D60(r0)
    fmadds f0, f1, f31, f0
    fmuls f1, f30, f0
    b _f3da4_end
_f3da4_q2:
    lfs f1, lbl_803E7D70(r0)
    lfs f0, lbl_803E7D6C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D68(r0)
    fmadds f1, f31, f1, f0
    b _f3da4_end
_f3da4_q4:
    lfs f1, lbl_803E7D64(r0)
    lfs f0, lbl_803E7D60(r0)
    fmadds f0, f1, f31, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f3da4_end
_f3da4_q3:
    lfs f1, lbl_803E7D70(r0)
    lfs f0, lbl_803E7D6C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D68(r0)
    fnmadds f1, f31, f1, f0
_f3da4_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}

asm float fn_80293E80(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    addi r11, r1, 0x20
    bl _savefpr_30
    stfs f1, 0x8(r1)
    addi r3, r1, 0xc
    lfs f1, 0x8(r1)
    bl fn_80292CC4
    fmr f30, f1
    lhz r4, 0xc(r1)
    lwz r3, 0x8(r1)
    rlwinm r0, r3, 3, 29, 29
    add r0, r4, r0
    sth r0, 0xc(r1)
    fmuls f31, f30, f30
    lhz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f3e80_q2
    bge _f3e80_ge
    cmpwi r0, 0
    beq _f3e80_q0
    b _f3e80_q3
_f3e80_ge:
    cmpwi r0, 0x4
    beq _f3e80_q4
    b _f3e80_q3
_f3e80_q0:
    lfs f1, lbl_803E7D7C(r0)
    lfs f0, lbl_803E7D78(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D74(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
    b _f3e80_end
_f3e80_q2:
    lfs f1, lbl_803E7D8C(r0)
    lfs f0, lbl_803E7D88(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D84(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fmadds f1, f31, f1, f0
    b _f3e80_end
_f3e80_q4:
    lfs f1, lbl_803E7D7C(r0)
    lfs f0, lbl_803E7D78(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D74(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f3e80_end
_f3e80_q3:
    lfs f1, lbl_803E7D8C(r0)
    lfs f0, lbl_803E7D88(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D84(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fnmadds f1, f31, f1, f0
_f3e80_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}

asm float fn_80293F7C(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    addi r11, r1, 0x20
    bl _savefpr_30
    stfs f1, 0x8(r1)
    addi r3, r1, 0xc
    lfs f1, 0x8(r1)
    bl fn_80292CC4
    fmr f30, f1
    lhz r4, 0xc(r1)
    lwz r3, 0x8(r1)
    rlwinm r0, r3, 3, 29, 29
    add r0, r4, r0
    sth r0, 0xc(r1)
    fmuls f31, f30, f30
    lhz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f3f7c_q2
    bge _f3f7c_ge
    cmpwi r0, 0
    beq _f3f7c_q0
    b _f3f7c_q3
_f3f7c_ge:
    cmpwi r0, 0x4
    beq _f3f7c_q4
    b _f3f7c_q3
_f3f7c_q0:
    lfs f1, lbl_803E7D9C(r0)
    lfs f0, lbl_803E7D98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D94(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D90(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
    b _f3f7c_end
_f3f7c_q2:
    lfs f1, lbl_803E7DAC(r0)
    lfs f0, lbl_803E7DA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7DA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7DA0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fmadds f1, f31, f1, f0
    b _f3f7c_end
_f3f7c_q4:
    lfs f1, lbl_803E7D9C(r0)
    lfs f0, lbl_803E7D98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D94(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D90(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f3f7c_end
_f3f7c_q3:
    lfs f1, lbl_803E7DAC(r0)
    lfs f0, lbl_803E7DA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7DA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7DA0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fnmadds f1, f31, f1, f0
_f3f7c_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}
