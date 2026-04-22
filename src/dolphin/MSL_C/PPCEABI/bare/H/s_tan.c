/*
 * Target bytes at this split are not Sun's MSL tan(). They're a small
 * angle-reduction helper: takes a pointer and a float, rounds the scaled
 * absolute value to an odd integer, writes it via the pointer, and returns
 * a refined float via fnmsub. Asm-only to preserve the exact byte image.
 */

extern unsigned int __cvt_fp2unsigned(double);
void _savefpr_30(void);
void _restfpr_30(void);

extern const double lbl_803E8898;
extern const double lbl_803E88A0;
extern const double lbl_803E88A8;

asm double tan(int* out_n, float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_30
    stw r31, 0x1c(r1)
    stw r3, 0x8(r1)
    stfs f1, 0xc(r1)
    lfs f0, 0xc(r1)
    fabs f31, f0
    lfd f0, lbl_803E8898(r0)
    fmul f30, f0, f31
    fmr f1, f30
    bl __cvt_fp2unsigned
    addi r0, r3, 0x1
    clrrwi r31, r0, 1
    lwz r3, 0x8(r1)
    stw r31, 0x0(r3)
    lfd f2, lbl_803E88A0(r0)
    lfd f1, lbl_803E88A8(r0)
    stw r31, 0x14(r1)
    lis r0, 0x4330
    stw r0, 0x10(r1)
    lfd f0, 0x10(r1)
    fsub f0, f0, f1
    fnmsub f1, f2, f0, f31
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_30
    lwz r31, 0x1c(r1)
    addi r1, r1, 0x30
    mtlr r0
    blr
}
