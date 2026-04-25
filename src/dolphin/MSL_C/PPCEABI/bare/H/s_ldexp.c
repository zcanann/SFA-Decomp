/*
 * Sun's ldexp from MSL — rewritten as asm to lock byte image to v1.0.
 * Sources two54/twom54/huge/tiny constants from sda2 lbl_803E7950..7970.
 */

extern double copysign(double, double);
extern const double lbl_803E7950;
extern const double lbl_803E7958;
extern const double lbl_803E7960;
extern const double lbl_803E7968;
extern const double lbl_803E7970;

asm double ldexp(double x, int n) {
    nofralloc
    stwu r1, -0x20(r1)
    mflr r0
    stfd f1, 0x10(r1)
    lwz r5, 0x10(r1)
    stw r0, 0x24(r1)
    lis r0, 0x7ff0
    rlwinm r4, r5, 0, 1, 11
    cmpw r4, r0
    stfd f1, 0x8(r1)
    beq _ldexp_eq_inf
    bge _ldexp_4
    cmpwi r4, 0x0
    beq _ldexp_lz
    b _ldexp_4
_ldexp_eq_inf:
    clrlwi. r0, r5, 12
    bne _ldexp_1
    lwz r0, 0x14(r1)
    cmpwi r0, 0x0
    beq _ldexp_2
_ldexp_1:
    li r0, 0x1
    b _ldexp_done_class
_ldexp_2:
    li r0, 0x2
    b _ldexp_done_class
_ldexp_lz:
    clrlwi. r0, r5, 12
    bne _ldexp_5
    lwz r0, 0x14(r1)
    cmpwi r0, 0x0
    beq _ldexp_3
_ldexp_5:
    li r0, 0x5
    b _ldexp_done_class
_ldexp_3:
    li r0, 0x3
    b _ldexp_done_class
_ldexp_4:
    li r0, 0x4
_ldexp_done_class:
    cmpwi r0, 0x2
    ble _ldexp_end
    lfd f0, lbl_803E7950(r0)
    fcmpu cr0, f0, f1
    bne _ldexp_a
    b _ldexp_end
_ldexp_a:
    lwz r5, 0x8(r1)
    lwz r6, 0xc(r1)
    extrwi. r4, r5, 11, 1
    bne _ldexp_b
    clrlwi r0, r5, 1
    or. r0, r6, r0
    bne _ldexp_c
    b _ldexp_end
_ldexp_c:
    lfd f1, 0x8(r1)
    lis r4, 0xffff
    lfd f0, lbl_803E7958(r0)
    addi r0, r4, 0x3cb0
    cmpw r3, r0
    fmul f1, f1, f0
    stfd f1, 0x8(r1)
    lwz r5, 0x8(r1)
    extrwi r4, r5, 11, 1
    subi r4, r4, 0x36
    bge _ldexp_b
    lfd f0, lbl_803E7960(r0)
    fmul f1, f0, f1
    b _ldexp_end
_ldexp_b:
    cmpwi r4, 0x7ff
    bne _ldexp_d
    lfd f0, 0x8(r1)
    fadd f1, f0, f0
    b _ldexp_end
_ldexp_d:
    add r4, r4, r3
    cmpwi r4, 0x7fe
    ble _ldexp_e
    lfd f1, lbl_803E7968(r0)
    lfd f2, 0x8(r1)
    bl copysign
    lfd f0, lbl_803E7968(r0)
    fmul f1, f0, f1
    b _ldexp_end
_ldexp_e:
    cmpwi r4, 0x0
    ble _ldexp_f
    rlwinm r3, r5, 0, 12, 0
    slwi r0, r4, 20
    or r0, r3, r0
    stw r0, 0x8(r1)
    lfd f1, 0x8(r1)
    b _ldexp_end
_ldexp_f:
    cmpwi r4, -0x36
    bgt _ldexp_g
    lis r4, 0x1
    subi r0, r4, 0x3cb0
    cmpw r3, r0
    ble _ldexp_h
    lfd f1, lbl_803E7968(r0)
    lfd f2, 0x8(r1)
    bl copysign
    lfd f0, lbl_803E7968(r0)
    fmul f1, f0, f1
    b _ldexp_end
_ldexp_h:
    lfd f1, lbl_803E7960(r0)
    lfd f2, 0x8(r1)
    bl copysign
    lfd f0, lbl_803E7960(r0)
    fmul f1, f0, f1
    b _ldexp_end
_ldexp_g:
    addi r0, r4, 0x36
    rlwinm r3, r5, 0, 12, 0
    slwi r0, r0, 20
    lfd f1, lbl_803E7970(r0)
    or r0, r3, r0
    stw r0, 0x8(r1)
    lfd f0, 0x8(r1)
    fmul f1, f1, f0
_ldexp_end:
    lwz r0, 0x24(r1)
    mtlr r0
    addi r1, r1, 0x20
    blr
}
