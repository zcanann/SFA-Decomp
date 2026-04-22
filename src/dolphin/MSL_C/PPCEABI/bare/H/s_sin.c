/*
 * Target bytes at this split are not Sun's MSL sin(). Game-side helper:
 * stores f1 to stack, calls fn_80293424 (shared helper) to get a short
 * quadrant in stack slot 0xc plus a reduced float in f1, switches on the
 * low two bits of the quadrant, and evaluates a per-quadrant polynomial.
 * Asm-only to preserve the exact byte image.
 */

extern float fn_80293424(short* out, float x);
void _savefpr_30(void);
void _restfpr_30(void);

extern const float lbl_803E8A0C;
extern const float lbl_803E8A10;
extern const float lbl_803E8A14;
extern const float lbl_803E8A18;
extern const float lbl_803E8A1C;
extern const float lbl_803E8A20;
extern const float lbl_803E8A24;

asm float sin(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    addi r11, r1, 0x20
    bl _savefpr_30
    stfs f1, 0x8(r1)
    addi r3, r1, 0xc
    lfs f1, 0x8(r1)
    bl fn_80293424
    fmr f30, f1
    fmuls f31, f30, f30
    lhz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _ss_2
    bge _ss_ge
    cmpwi r0, 0x0
    beq _ss_0
    b _ss_d
_ss_ge:
    cmpwi r0, 0x4
    beq _ss_4
    b _ss_d
_ss_0:
    lfs f1, lbl_803E8A24(r0)
    lfs f0, lbl_803E8A20(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8A1C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8A18(r0)
    fmadds f1, f31, f1, f0
    b _ss_end
_ss_2:
    lfs f1, lbl_803E8A14(r0)
    lfs f0, lbl_803E8A10(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8A0C(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _ss_end
_ss_4:
    lfs f1, lbl_803E8A24(r0)
    lfs f0, lbl_803E8A20(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8A1C(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8A18(r0)
    fnmadds f1, f31, f1, f0
    b _ss_end
_ss_d:
    lfs f1, lbl_803E8A14(r0)
    lfs f0, lbl_803E8A10(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8A0C(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
_ss_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}
