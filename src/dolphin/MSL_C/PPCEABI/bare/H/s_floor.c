/*
 * Target bytes at this split are not Sun's MSL floor(). Game-side helper
 * that calls tan (another mislabeled game-side func at s_tan.c) to get an
 * int quadrant, xors a rounding bit, then runs a per-quadrant double-poly
 * and rounds to float. Asm-only to preserve the exact byte image.
 */

extern double tan(int* out_n, float x);
void _savefpr_30(void);
void _restfpr_30(void);

extern const double lbl_803E7DB0;
extern const double lbl_803E7DB8;
extern const double lbl_803E7DC0;
extern const double lbl_803E7DC8;
extern const double lbl_803E7DD0;
extern const double lbl_803E7DD8;
extern const double lbl_803E7DE0;
extern const double lbl_803E7DE8;
extern const double lbl_803E7DF0;
extern const double lbl_803E7DF8;
extern const double lbl_803E7E00;
extern const double lbl_803E7E08;
extern const double lbl_803E7E10;

asm float floor(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    addi r11, r1, 0x20
    bl _savefpr_30
    stfs f1, 0x8(r1)
    addi r3, r1, 0xc
    lfs f1, 0x8(r1)
    bl tan
    fmr f30, f1
    lwz r4, 0xc(r1)
    lwz r3, 0x8(r1)
    rlwinm r0, r3, 3, 29, 29
    add r0, r4, r0
    stw r0, 0xc(r1)
    fmul f31, f30, f30
    lwz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _sf_2
    bge _sf_ge
    cmpwi r0, 0x0
    beq _sf_0
    b _sf_d
_sf_ge:
    cmpwi r0, 0x4
    beq _sf_4
    b _sf_d
_sf_0:
    lfd f1, lbl_803E7DD8(r0)
    lfd f0, lbl_803E7DD0(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7DC8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DC0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DB8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DB0(r0)
    fmadd f0, f31, f1, f0
    fmul f1, f30, f0
    frsp f1, f1
    b _sf_end
_sf_2:
    lfd f1, lbl_803E7E10(r0)
    lfd f0, lbl_803E7E08(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7E00(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DF8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DE0(r0)
    fmadd f1, f31, f1, f0
    frsp f1, f1
    b _sf_end
_sf_4:
    lfd f1, lbl_803E7DD8(r0)
    lfd f0, lbl_803E7DD0(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7DC8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DC0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DB8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DB0(r0)
    fmadd f0, f31, f1, f0
    fmul f0, f30, f0
    fneg f1, f0
    frsp f1, f1
    b _sf_end
_sf_d:
    lfd f1, lbl_803E7E10(r0)
    lfd f0, lbl_803E7E08(r0)
    fmadd f1, f1, f31, f0
    lfd f0, lbl_803E7E00(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DF8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DF0(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DE8(r0)
    fmadd f1, f31, f1, f0
    lfd f0, lbl_803E7DE0(r0)
    fnmadd f1, f31, f1, f0
    frsp f1, f1
_sf_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}
