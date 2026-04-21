/*
 * Target bytes at this split are not UART console I/O. __write_console
 * is a log2-ish helper: log-extracts exponent from a float, optionally
 * adjusts via fn_80292568/fn_80292584, then evaluates a 4-term poly and
 * recombines via exponent bit-fiddling. The tail 8-byte gap is just
 * mtlr r0; blr. Asm-only to preserve the exact byte image.
 */

extern float fn_80292584(float x, short* out);
extern float fn_80292568(short* x);
void _savefpr_29(void);
void _restfpr_29(void);

extern const float lbl_803E8610;
extern const float lbl_803E8614;
extern const float lbl_803E8618;
extern const float lbl_803E861C;
extern const float lbl_803E8620;
extern const float lbl_803E8624;
extern const float lbl_803E8628;
extern const float lbl_803E862C;

asm float __write_console(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_29
    fmr f30, f1
    lfs f0, lbl_803E8610(r0)
    fcmpo cr0, f30, f0
    bge _uc_0
    lfs f1, lbl_803E8614(r0)
    b _uc_end
_uc_0:
    fmr f1, f30
    addi r3, r1, 0x10
    bl fn_80292584
    addi r3, r1, 0x10
    bl fn_80292568
    fmr f29, f1
    fsubs f31, f30, f29
    lfs f0, lbl_803E8614(r0)
    fcmpu cr0, f31, f0
    beq _uc_1
    lfs f0, lbl_803E8614(r0)
    fcmpo cr0, f30, f0
    bge _uc_2
    lha r3, 0x10(r1)
    subi r0, r3, 0x1
    sth r0, 0x10(r1)
    lfs f0, lbl_803E8618(r0)
    fadds f31, f31, f0
_uc_2:
    lfs f1, lbl_803E862C(r0)
    lfs f0, lbl_803E8628(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E8624(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E8620(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E861C(r0)
    fmadds f0, f31, f1, f0
    stfs f0, 0xc(r1)
    b _uc_3
_uc_1:
    lfs f0, lbl_803E8618(r0)
    stfs f0, 0xc(r1)
_uc_3:
    lwz r3, 0xc(r1)
    lha r0, 0x10(r1)
    slwi r0, r0, 23
    add r0, r3, r0
    stw r0, 0xc(r1)
    lfs f1, 0xc(r1)
_uc_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_29
    addi r1, r1, 0x30
}

asm void gap_03_80292530_text(void) {
    nofralloc
    mtlr r0
    blr
}
