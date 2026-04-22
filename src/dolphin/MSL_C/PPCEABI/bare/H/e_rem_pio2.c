/*
 * The target bytes at this split are not Sun's IEEE-754 remainder of x/(pi/2)
 * implementation. They're three fixed-point-angle sin/cos/tan-like polynomial
 * dispatchers (same pattern as k_tan.c's fn_80293994): switch on the top 3
 * bits of an int angle (0x0/0x2000/0x4000/0x6000/0x8000/0xE000), call
 * fn_80292568 to convert the short to a float, then evaluate a quadrant-
 * specific polynomial. __ieee754_rem_pio2/fn_80293D0C/fn_80293EAC differ only
 * in precision (float vs double) and coefficient set. Asm-only to preserve
 * the exact byte image.
 */

extern float fn_80292568(short* x);
void _savefpr_29(void);
void _savefpr_30(void);
void _restfpr_29(void);
void _restfpr_30(void);

extern const float lbl_803E8938;
extern const float lbl_803E8948;
extern const float lbl_803E894C;
extern const float lbl_803E8950;
extern const float lbl_803E8954;
extern const float lbl_803E8958;
extern const float lbl_803E895C;
extern const float lbl_803E8960;
extern const float lbl_803E8964;
extern const double lbl_803E8968;
extern const double lbl_803E8970;
extern const double lbl_803E8978;
extern const double lbl_803E8980;
extern const double lbl_803E8988;
extern const double lbl_803E8990;
extern const double lbl_803E8998;
extern const double lbl_803E89A0;
extern const double lbl_803E89A8;
extern const double lbl_803E89B0;
extern const double lbl_803E89B8;
extern const double lbl_803E89C0;
extern const double lbl_803E89C8;
extern const double lbl_803E89D0;
extern const float lbl_803E8918;
extern const float lbl_803E891C;
extern const float lbl_803E8920;
extern const float lbl_803E8924;
extern const float lbl_803E8928;

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
    bl fn_80292568
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
    lfs f1, lbl_803E8954(r0)
    lfs f0, lbl_803E8950(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E894C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8948(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
    b _erp1_end
_erp1_b:
    lfs f1, lbl_803E8964(r0)
    lfs f0, lbl_803E8960(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E895C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8958(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8938(r0)
    fmadds f1, f31, f1, f0
    b _erp1_end
_erp1_a:
    lfs f1, lbl_803E8954(r0)
    lfs f0, lbl_803E8950(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E894C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8948(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _erp1_end
_erp1_d:
    lfs f1, lbl_803E8964(r0)
    lfs f0, lbl_803E8960(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E895C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8958(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8938(r0)
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
    bl fn_80292568
    fmr f29, f1
    lfd f0, lbl_803E8968(r0)
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
    lfd f1, lbl_803E8998(r0)
    lfd f0, lbl_803E8990(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E8988(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8980(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8978(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8970(r0)
    fmadd f0, f31, f1, f0
    fmul f1, f30, f0
    frsp f1, f1
    b _erp2_end
_erp2_b:
    lfd f1, lbl_803E89D0(r0)
    lfd f0, lbl_803E89C8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E89C0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89B8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89B0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89A8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89A0(r0)
    fmadd f1, f31, f1, f0
    frsp f1, f1
    b _erp2_end
_erp2_a:
    lfd f1, lbl_803E8998(r0)
    lfd f0, lbl_803E8990(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E8988(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8980(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8978(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E8970(r0)
    fmadd f0, f31, f1, f0
    fmul f0, f30, f0
    fneg f1, f0
    frsp f1, f1
    b _erp2_end
_erp2_d:
    lfd f1, lbl_803E89D0(r0)
    lfd f0, lbl_803E89C8(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E89C0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89B8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89B0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89A8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E89A0(r0)
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
    bl fn_80292568
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
    lfs f1, lbl_803E8920(r0)
    lfs f0, lbl_803E891C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8918(r0)
    fmadds f1, f31, f1, f0
    b _erp3_end
_erp3_b:
    lfs f1, lbl_803E8928(r0)
    lfs f0, lbl_803E8924(r0)
    fmadds f0, f1, f31, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _erp3_end
_erp3_a:
    lfs f1, lbl_803E8920(r0)
    lfs f0, lbl_803E891C(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8918(r0)
    fnmadds f1, f31, f1, f0
    b _erp3_end
_erp3_d:
    lfs f1, lbl_803E8928(r0)
    lfs f0, lbl_803E8924(r0)
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
