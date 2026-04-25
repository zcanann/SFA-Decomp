/*
 * Target bytes at this split are not Sun's MSL sin(). Game-side helper:
 * stores f1 to stack, calls fn_80292CC4 (shared helper) to get a short
 * quadrant in stack slot 0xc plus a reduced float in f1, switches on the
 * low two bits of the quadrant, and evaluates a per-quadrant polynomial.
 * Asm-only to preserve the exact byte image.
 */

extern float fn_80292CC4(short* out, float x);
extern float fn_80292CC4(short* out, float x);
extern float fn_80291E08(short* p);
extern float tan(short* out, float x);
void _savefpr_28(void);
void _restfpr_28(void);
void _savefpr_30(void);
void _restfpr_30(void);

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
extern const float lbl_803E7E18;
extern const float lbl_803E7E1C;
extern const float lbl_803E7E20;
extern const float lbl_803E7E24;
extern const float lbl_803E7E28;
extern const float lbl_803E7E2C;
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
    bl fn_80292CC4
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
    lfs f1, lbl_803E7D8C(r0)
    lfs f0, lbl_803E7D88(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D84(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fmadds f1, f31, f1, f0
    b _ss_end
_ss_2:
    lfs f1, lbl_803E7D7C(r0)
    lfs f0, lbl_803E7D78(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D74(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _ss_end
_ss_4:
    lfs f1, lbl_803E7D8C(r0)
    lfs f0, lbl_803E7D88(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D84(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fnmadds f1, f31, f1, f0
    b _ss_end
_ss_d:
    lfs f1, lbl_803E7D7C(r0)
    lfs f0, lbl_803E7D78(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D74(r0)
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

asm float fn_802942EC(float x) {
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
    fmuls f31, f30, f30
    lhz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f42ec_2
    bge _f42ec_ge
    cmpwi r0, 0x0
    beq _f42ec_0
    b _f42ec_d
_f42ec_ge:
    cmpwi r0, 0x4
    beq _f42ec_4
    b _f42ec_d
_f42ec_0:
    lfs f1, lbl_803E7DAC(r0)
    lfs f0, lbl_803E7DA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7DA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7DA0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fmadds f1, f31, f1, f0
    b _f42ec_end
_f42ec_2:
    lfs f1, lbl_803E7D9C(r0)
    lfs f0, lbl_803E7D98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D94(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D90(r0)
    fmadds f0, f31, f1, f0
    fmuls f0, f30, f0
    fneg f1, f0
    b _f42ec_end
_f42ec_4:
    lfs f1, lbl_803E7DAC(r0)
    lfs f0, lbl_803E7DA8(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7DA4(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7DA0(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D80(r0)
    fnmadds f1, f31, f1, f0
    b _f42ec_end
_f42ec_d:
    lfs f1, lbl_803E7D9C(r0)
    lfs f0, lbl_803E7D98(r0)
    fmadds f1, f1, f31, f0
    lfs f0, lbl_803E7D94(r0)
    fmadds f1, f31, f1, f0
    lfs f0, lbl_803E7D90(r0)
    fmadds f0, f31, f1, f0
    fmuls f1, f30, f0
_f42ec_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}

asm float fn_802943F4(float x) {
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
    fmul f31, f30, f30
    lwz r0, 0xc(r1)
    rlwinm r0, r0, 0, 29, 30
    cmpwi r0, 0x2
    beq _f43f4_2
    bge _f43f4_ge
    cmpwi r0, 0x0
    beq _f43f4_0
    b _f43f4_d
_f43f4_ge:
    cmpwi r0, 0x4
    beq _f43f4_4
    b _f43f4_d
_f43f4_0:
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
    b _f43f4_end
_f43f4_2:
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
    b _f43f4_end
_f43f4_4:
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
    b _f43f4_end
_f43f4_d:
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
_f43f4_end:
    lwz r0, 0x24(r1)
    addi r11, r1, 0x20
    bl _restfpr_30
    addi r1, r1, 0x20
    mtlr r0
    blr
}

asm float fn_8029454C(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x30(r1)
    addi r11, r1, 0x30
    bl _savefpr_28
    fmr f28, f1
    addi r3, r1, 0xc
    fmr f1, f28
    bl fn_80292CC4
    fmr f30, f1
    fmuls f29, f30, f30
    lfs f1, lbl_803E7E2C(r0)
    lfs f0, lbl_803E7E28(r0)
    fmadds f1, f1, f29, f0
    lfs f0, lbl_803E7E24(r0)
    fmadds f1, f29, f1, f0
    lfs f0, lbl_803E7E20(r0)
    fmadds f0, f29, f1, f0
    fmuls f31, f30, f0
    lhz r0, 0xc(r1)
    rlwinm. r0, r0, 0, 30, 30
    beq _f454c_0
    lfs f0, lbl_803E7E18(r0)
    fdivs f31, f0, f31
_f454c_0:
    lfs f0, lbl_803E7E1C(r0)
    fcmpo cr0, f28, f0
    cror 2, 1, 2
    bne _f454c_neg
    fmr f1, f31
    b _f454c_end
_f454c_neg:
    fneg f1, f31
_f454c_end:
    lwz r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _restfpr_28
    addi r1, r1, 0x30
    mtlr r0
    blr
}

asm float fn_802945E0(float x) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    stfd f31, 0x20(r1)
    stw r31, 0x1c(r1)
    stfs f1, 0x8(r1)
    lwz r31, 0x8(r1)
    extrwi r3, r31, 8, 1
    subi r0, r3, 0x80
    sth r0, 0xc(r1)
    clrlwi r0, r31, 9
    oris r0, r0, 0x3f80
    stw r0, 0x10(r1)
    addi r3, r1, 0xc
    bl fn_80291E08
    fmr f31, f1
    lfs f0, 0x10(r1)
    fadds f1, f0, f31
    lwz r0, 0x2c(r1)
    lfd f31, 0x20(r1)
    lwz r31, 0x1c(r1)
    addi r1, r1, 0x28
    mtlr r0
    blr
}
