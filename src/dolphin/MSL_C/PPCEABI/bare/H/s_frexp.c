/*
 * Sun's frexp from MSL — rewritten as asm to lock byte image to v1.0.
 * Sources two54 from sda2 lbl_803E7948 (matches v1.0 link layout).
 */

extern const double lbl_803E7948;

asm double frexp(double x, int* eptr) {
    nofralloc
    stwu r1, -0x10(r1)
    li r4, 0x0
    lis r0, 0x7ff0
    stfd f1, 0x8(r1)
    lwz r5, 0x8(r1)
    stw r4, 0x0(r3)
    clrlwi r4, r5, 1
    lwz r6, 0xc(r1)
    cmpw r4, r0
    bge _frexp_inf
    or. r0, r4, r6
    bne _frexp_normal
_frexp_inf:
    lfd f1, 0x8(r1)
    b _frexp_done
_frexp_normal:
    lis r0, 0x10
    cmpw r4, r0
    bge _frexp_skip_sub
    lfd f0, lbl_803E7948(r0)
    li r0, -0x36
    stw r0, 0x0(r3)
    fmul f0, f1, f0
    stfd f0, 0x8(r1)
    lwz r5, 0x8(r1)
    clrlwi r4, r5, 1
_frexp_skip_sub:
    rlwinm r0, r5, 0, 12, 0
    lwz r5, 0x0(r3)
    srawi r4, r4, 20
    oris r0, r0, 0x3fe0
    stw r0, 0x8(r1)
    add r4, r4, r5
    subi r0, r4, 0x3fe
    stw r0, 0x0(r3)
    lfd f1, 0x8(r1)
_frexp_done:
    addi r1, r1, 0x10
    blr
}
