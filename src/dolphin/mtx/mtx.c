#include "dolphin/mtx.h"

static f32 lbl_803DC550[] = { 0.0f, 1.0f };

extern const f32 lbl_803E7618;
extern const f32 lbl_803E761C;
extern const f32 lbl_803E7620;
extern const f32 lbl_803E7624;
extern const f32 lbl_803E7628;
extern const f32 lbl_803E762C;

extern f32 sinf(f32);
extern f32 cosf(f32);
extern f32 tanf(f32);

extern void fn_80246E54(void);
extern void fn_80246E80(void);
extern void fn_80246EB4(void);
extern void fn_80246F80(void);
extern void fn_80246FD0(void);
extern void fn_802470C8(void);
extern void fn_80247138(void);
extern void fn_802471E0(void);
extern void fn_802472E4(void);
extern void fn_80247318(void);
extern void fn_80247340(void);
extern void fn_8024740C(void);

#ifdef GEKKO
asm void PSMTXIdentity(register Mtx m)
{
    nofralloc
entry fn_80246E54
    lfs f0, lbl_803E761C(r2)
    lfs f1, lbl_803E7618(r2)
    psq_st f0, 0x8(r3), 0, 0
    ps_merge01 f2, f0, f1
    psq_st f0, 0x18(r3), 0, 0
    ps_merge10 f1, f1, f0
    psq_st f0, 0x20(r3), 0, 0
    psq_st f2, 0x10(r3), 0, 0
    psq_st f1, 0x0(r3), 0, 0
    psq_st f1, 0x28(r3), 0, 0
    blr
}

asm void PSMTXCopy(const register Mtx src, register Mtx dst)
{
    nofralloc
entry fn_80246E80
    psq_l f0, 0(src), 0, 0
    psq_st f0, 0(dst), 0, 0
    psq_l f1, 8(src), 0, 0
    psq_st f1, 8(dst), 0, 0
    psq_l f2, 16(src), 0, 0
    psq_st f2, 16(dst), 0, 0
    psq_l f3, 24(src), 0, 0
    psq_st f3, 24(dst), 0, 0
    psq_l f4, 32(src), 0, 0
    psq_st f4, 32(dst), 0, 0
    psq_l f5, 40(src), 0, 0
    psq_st f5, 40(dst), 0, 0
    blr
}

asm void PSMTXConcat(const register Mtx mA, const register Mtx mB, register Mtx mAB)
{
    nofralloc
entry fn_80246EB4
    stwu    r1, -64(r1)
    psq_l   fp0, 0(mA), 0, 0
    stfd    fp14, 8(r1)
    psq_l   fp6, 0(mB), 0, 0
    addis   r6, 0, lbl_803DC550@ha
    psq_l   fp7, 8(mB), 0, 0
    stfd    fp15, 16(r1)
    addi    r6, r6, lbl_803DC550@l
    stfd    fp31, 40(r1)
    psq_l   fp8, 16(mB), 0, 0
    ps_muls0 fp12, fp6, fp0
    psq_l   fp2, 16(mA), 0, 0
    ps_muls0 fp13, fp7, fp0
    psq_l   fp31, 0(r6), 0, 0
    ps_muls0 fp14, fp6, fp2
    psq_l   fp9, 24(mB), 0, 0
    ps_muls0 fp15, fp7, fp2
    psq_l   fp1, 8(mA), 0, 0
    ps_madds1 fp12, fp8, fp0, fp12
    psq_l   fp3, 24(mA), 0, 0
    ps_madds1 fp14, fp8, fp2, fp14
    psq_l   fp10, 32(mB), 0, 0
    ps_madds1 fp13, fp9, fp0, fp13
    psq_l   fp11, 40(mB), 0, 0
    ps_madds1 fp15, fp9, fp2, fp15
    psq_l   fp4, 32(mA), 0, 0
    psq_l   fp5, 40(mA), 0, 0
    ps_madds0 fp12, fp10, fp1, fp12
    ps_madds0 fp13, fp11, fp1, fp13
    ps_madds0 fp14, fp10, fp3, fp14
    ps_madds0 fp15, fp11, fp3, fp15
    psq_st  fp12, 0(mAB), 0, 0
    ps_muls0 fp2, fp6, fp4
    ps_madds1 fp13, fp31, fp1, fp13
    ps_muls0 fp0, fp7, fp4
    psq_st  fp14, 16(mAB), 0, 0
    ps_madds1 fp15, fp31, fp3, fp15
    psq_st  fp13, 8(mAB), 0, 0
    ps_madds1 fp2, fp8, fp4, fp2
    ps_madds1 fp0, fp9, fp4, fp0
    ps_madds0 fp2, fp10, fp5, fp2
    lfd    fp14, 8(r1)
    psq_st  fp15, 24(mAB), 0, 0
    ps_madds0 fp0, fp11, fp5, fp0
    psq_st  fp2, 32(mAB), 0, 0
    ps_madds1 fp0, fp31, fp5, fp0
    lfd    fp15, 16(r1)
    psq_st  fp0, 40(mAB), 0, 0
    lfd    fp31, 40(r1)
    addi   r1, r1, 64
    blr
}

asm void PSMTXTranspose(const register Mtx src, register Mtx xPose)
{
    nofralloc
entry fn_80246F80
    lfs f0, lbl_803E761C(r2)
    psq_l f1, 0(src), 0, 0
    stfs f0, 44(xPose)
    psq_l f2, 16(src), 0, 0
    ps_merge00 f4, f1, f2
    psq_l f3, 8(src), 1, 0
    ps_merge11 f5, f1, f2
    psq_l f2, 24(src), 1, 0
    psq_st f4, 0(xPose), 0, 0
    psq_l f1, 32(src), 0, 0
    ps_merge00 f2, f3, f2
    psq_st f5, 16(xPose), 0, 0
    ps_merge00 f4, f1, f0
    psq_st f2, 32(xPose), 0, 0
    ps_merge10 f5, f1, f0
    psq_st f4, 8(xPose), 0, 0
    lfs f3, 40(src)
    psq_st f5, 24(xPose), 0, 0
    stfs f3, 40(xPose)
    blr
}

asm u32 PSMTXInverse(const register Mtx src, register Mtx inv)
{
    nofralloc
entry fn_80246FD0
    psq_l       fp0, 0(src), 1, 0
    psq_l       fp1, 4(src), 0, 0
    psq_l       fp2, 16(src), 1, 0
    ps_merge10  fp6, fp1, fp0
    psq_l       fp3, 20(src), 0, 0
    psq_l       fp4, 32(src), 1, 0
    ps_merge10  fp7, fp3, fp2
    psq_l       fp5, 36(src), 0, 0
    ps_mul      fp11, fp3, fp6
    ps_mul      fp13, fp5, fp7
    ps_merge10  fp8, fp5, fp4
    ps_msub     fp11, fp1, fp7, fp11
    ps_mul      fp12, fp1, fp8
    ps_msub     fp13, fp3, fp8, fp13
    ps_mul      fp10, fp3, fp4
    ps_msub     fp12, fp5, fp6, fp12
    ps_mul      fp9,  fp0, fp5
    ps_mul      fp8,  fp1, fp2
    ps_sub      fp6, fp6, fp6
    ps_msub     fp10, fp2, fp5, fp10
    ps_mul      fp7, fp0, fp13
    ps_msub     fp9,  fp1, fp4, fp9
    ps_madd     fp7, fp2, fp12, fp7
    ps_msub     fp8,  fp0, fp3, fp8
    ps_madd     fp7, fp4, fp11, fp7
    ps_cmpo0    cr0, fp7, fp6
    bne         _regular
    addi        r3, 0, 0
    blr
_regular:
    fres        fp0, fp7
    ps_add      fp6, fp0, fp0
    ps_mul      fp5, fp0, fp0
    ps_nmsub    fp0, fp7, fp5, fp6
    lfs         fp1, 12(src)
    ps_muls0    fp13, fp13, fp0
    lfs         fp2, 28(src)
    ps_muls0    fp12, fp12, fp0
    lfs         fp3, 44(src)
    ps_muls0    fp11, fp11, fp0
    ps_merge00  fp5, fp13, fp12
    ps_muls0    fp10, fp10, fp0
    ps_merge11  fp4, fp13, fp12
    ps_muls0    fp9,  fp9,  fp0
    psq_st      fp5,  0(inv), 0, 0
    ps_mul      fp6, fp13, fp1
    psq_st      fp4,  16(inv), 0, 0
    ps_muls0    fp8,  fp8,  fp0
    ps_madd     fp6, fp12, fp2, fp6
    psq_st      fp10, 32(inv), 1, 0
    ps_nmadd    fp6, fp11, fp3, fp6
    psq_st      fp9,  36(inv), 1, 0
    ps_mul      fp7, fp10, fp1
    ps_merge00  fp5, fp11, fp6
    psq_st      fp8,  40(inv), 1, 0
    ps_merge11  fp4, fp11, fp6
    psq_st      fp5,  8(inv), 0, 0
    ps_madd     fp7, fp9,  fp2, fp7
    psq_st      fp4,  24(inv), 0, 0
    ps_nmadd    fp7, fp8,  fp3, fp7
    addi        r3, 0, 1
    psq_st      fp7,  44(inv), 1, 0
    blr
}

asm void PSMTXRotRad(Mtx m, char axis, f32 rad)
{
    nofralloc
entry fn_802470C8
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x28(r1)
    stfd f31, 0x20(r1)
    stw r31, 0x1c(r1)
    stw r30, 0x18(r1)
    fmr f31, f1
    mr r30, r3
    mr r31, r4
    fmr f1, f31
    bl sinf
    fmr f0, f1
    fmr f1, f31
    fmr f31, f0
    bl cosf
    fmr f0, f1
    mr r3, r30
    fmr f1, f31
    mr r4, r31
    fmr f2, f0
    bl PSMTXRotTrig
    lwz r0, 0x2c(r1)
    lfd f31, 0x20(r1)
    lwz r31, 0x1c(r1)
    mtlr r0
    lwz r30, 0x18(r1)
    addi r1, r1, 0x28
    blr
}

asm void PSMTXRotTrig(register Mtx m, register char axis, register f32 sinA, register f32 cosA)
{
    nofralloc
entry fn_80247138
    lfs f0, lbl_803E761C(r2)
    lfs f3, lbl_803E7618(r2)
    ori r0, r4, 0x20
    ps_neg f4, f1
    cmplwi r0, 0x78
    beq _prt_x
    cmplwi r0, 0x79
    beq _prt_y
    cmplwi r0, 0x7a
    beq _prt_z
    b _prt_end
_prt_x:
    psq_st f3, 0x0(r3), 1, 0
    psq_st f0, 0x4(r3), 0, 0
    ps_merge00 f5, f1, f2
    psq_st f0, 0xc(r3), 0, 0
    ps_merge00 f2, f2, f4
    psq_st f0, 0x1c(r3), 0, 0
    psq_st f0, 0x2c(r3), 1, 0
    psq_st f5, 0x24(r3), 0, 0
    psq_st f2, 0x14(r3), 0, 0
    b _prt_end
_prt_y:
    ps_merge00 f5, f2, f0
    ps_merge00 f2, f0, f3
    psq_st f0, 0x18(r3), 0, 0
    psq_st f5, 0x0(r3), 0, 0
    ps_merge00 f4, f4, f0
    ps_merge00 f0, f1, f0
    psq_st f5, 0x28(r3), 0, 0
    psq_st f2, 0x10(r3), 0, 0
    psq_st f0, 0x8(r3), 0, 0
    psq_st f4, 0x20(r3), 0, 0
    b _prt_end
_prt_z:
    psq_st f0, 0x8(r3), 0, 0
    ps_merge00 f5, f1, f2
    ps_merge00 f4, f2, f4
    psq_st f0, 0x18(r3), 0, 0
    psq_st f0, 0x20(r3), 0, 0
    ps_merge00 f2, f3, f0
    psq_st f5, 0x10(r3), 0, 0
    psq_st f4, 0x0(r3), 0, 0
    psq_st f2, 0x28(r3), 0, 0
_prt_end:
    blr
}

asm void PSMTXRotAxisRad(register Mtx m, const Vec *axis, register f32 rad)
{
    nofralloc
entry fn_802471E0
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x58(r1)
    stfd f31, 0x50(r1)
    stfd f30, 0x48(r1)
    stfd f29, 0x40(r1)
    stfd f28, 0x38(r1)
    stfd f27, 0x30(r1)
    stw r31, 0x2c(r1)
    stw r30, 0x28(r1)
    stw r29, 0x24(r1)
    fmr f27, f1
    mr r29, r3
    mr r30, r4
    fmr f1, f27
    lfs f28, lbl_803E761C(r2)
    addi r31, r1, 0x14
    bl sinf
    fmr f30, f1
    fmr f1, f27
    bl cosf
    fmr f31, f1
    lfs f0, lbl_803E7618(r2)
    mr r3, r30
    mr r4, r31
    fsubs f29, f0, f31
    bl PSVECNormalize
    psq_l f27, 0x0(r31), 0, 0
    lfs f1, 0x1c(r1)
    ps_merge00 f0, f31, f31
    ps_muls0 f4, f27, f29
    ps_muls0 f5, f1, f29
    ps_muls1 f3, f4, f27
    ps_muls0 f2, f4, f27
    ps_muls0 f27, f27, f30
    ps_muls0 f4, f4, f1
    fnmsubs f6, f1, f30, f3
    fmadds f7, f1, f30, f3
    ps_neg f9, f27
    ps_sum0 f8, f4, f28, f27
    ps_sum0 f2, f2, f6, f0
    ps_sum1 f3, f0, f7, f3
    ps_sum0 f6, f9, f28, f4
    ps_sum0 f9, f4, f4, f9
    psq_st f8, 0x8(r29), 0, 0
    ps_muls0 f5, f5, f1
    psq_st f2, 0x0(r29), 0, 0
    ps_sum1 f4, f27, f9, f4
    psq_st f3, 0x10(r29), 0, 0
    ps_sum0 f5, f5, f28, f0
    psq_st f6, 0x18(r29), 0, 0
    psq_st f4, 0x20(r29), 0, 0
    psq_st f5, 0x28(r29), 0, 0
    lwz r0, 0x5c(r1)
    lfd f31, 0x50(r1)
    lfd f30, 0x48(r1)
    mtlr r0
    lfd f29, 0x40(r1)
    lfd f28, 0x38(r1)
    lfd f27, 0x30(r1)
    lwz r31, 0x2c(r1)
    lwz r30, 0x28(r1)
    lwz r29, 0x24(r1)
    addi r1, r1, 0x58
    blr
}

asm void PSMTXTrans(register Mtx m, register f32 xT, register f32 yT, register f32 zT)
{
    nofralloc
entry fn_802472E4
    lfs f0, lbl_803E761C(r2)
    lfs f4, lbl_803E7618(r2)
    stfs f1, 0xc(r3)
    stfs f2, 0x1c(r3)
    psq_st f0, 0x4(r3), 0, 0
    psq_st f0, 0x20(r3), 0, 0
    stfs f0, 0x10(r3)
    stfs f4, 0x14(r3)
    stfs f0, 0x18(r3)
    stfs f4, 0x28(r3)
    stfs f3, 0x2c(r3)
    stfs f4, 0x0(r3)
    blr
}

asm void PSMTXScale(register Mtx m, register f32 xS, register f32 yS, register f32 zS)
{
    nofralloc
entry fn_80247318
    lfs f0, lbl_803E761C(r2)
    stfs f1, 0x0(r3)
    psq_st f0, 0x4(r3), 0, 0
    psq_st f0, 0xc(r3), 0, 0
    stfs f2, 0x14(r3)
    psq_st f0, 0x18(r3), 0, 0
    psq_st f0, 0x20(r3), 0, 0
    stfs f3, 0x28(r3)
    stfs f0, 0x2c(r3)
    blr
}

asm void C_MTXLightPerspective(Mtx m, f32 fovY, f32 aspect, float scaleS, float scaleT, float transS, float transT)
{
    nofralloc
entry fn_80247340
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x58(r1)
    stfd f31, 0x50(r1)
    stfd f30, 0x48(r1)
    stfd f29, 0x40(r1)
    stfd f28, 0x38(r1)
    stfd f27, 0x30(r1)
    stw r31, 0x2c(r1)
    fmr f27, f2
    mr r31, r3
    fmr f28, f3
    fmr f29, f4
    fmr f30, f5
    fmr f31, f6
    lfs f2, lbl_803E7628(r2)
    lfs f0, lbl_803E762C(r2)
    fmuls f1, f2, f1
    fmuls f1, f0, f1
    bl tanf
    lfs f3, lbl_803E7618(r2)
    fneg f2, f30
    fneg f0, f31
    fdivs f4, f3, f1
    fdivs f1, f4, f27
    fmuls f3, f28, f1
    fmuls f1, f4, f29
    stfs f3, 0x0(r31)
    lfs f3, lbl_803E761C(r2)
    stfs f3, 0x4(r31)
    stfs f2, 0x8(r31)
    stfs f3, 0xc(r31)
    stfs f3, 0x10(r31)
    stfs f1, 0x14(r31)
    stfs f0, 0x18(r31)
    stfs f3, 0x1c(r31)
    stfs f3, 0x20(r31)
    stfs f3, 0x24(r31)
    lfs f0, lbl_803E7624(r2)
    stfs f0, 0x28(r31)
    stfs f3, 0x2c(r31)
    lwz r0, 0x5c(r1)
    lfd f31, 0x50(r1)
    lfd f30, 0x48(r1)
    mtlr r0
    lfd f29, 0x40(r1)
    lfd f28, 0x38(r1)
    lfd f27, 0x30(r1)
    lwz r31, 0x2c(r1)
    addi r1, r1, 0x58
    blr
}

asm void C_MTXLightOrtho(Mtx m, f32 t, f32 b, f32 l, f32 r, float scaleS, float scaleT, float transS, float transT)
{
    nofralloc
entry fn_8024740C
    fsubs f10, f4, f3
    lfs f11, lbl_803E7618(r2)
    fsubs f0, f1, f2
    lfs f9, lbl_803E7620(r2)
    fadds f3, f4, f3
    fdivs f12, f11, f10
    fdivs f10, f11, f0
    fmuls f4, f9, f12
    fneg f3, f3
    fadds f0, f1, f2
    fmuls f1, f4, f5
    fmuls f2, f12, f3
    fneg f0, f0
    stfs f1, 0x0(r3)
    fmuls f1, f9, f10
    fmuls f2, f5, f2
    lfs f3, lbl_803E761C(r2)
    fmuls f0, f10, f0
    stfs f3, 0x4(r3)
    fadds f2, f7, f2
    fmuls f1, f1, f6
    stfs f3, 0x8(r3)
    fmuls f0, f6, f0
    stfs f2, 0xc(r3)
    stfs f3, 0x10(r3)
    fadds f0, f8, f0
    stfs f1, 0x14(r3)
    stfs f3, 0x18(r3)
    stfs f0, 0x1c(r3)
    stfs f3, 0x20(r3)
    stfs f3, 0x24(r3)
    stfs f3, 0x28(r3)
    stfs f11, 0x2c(r3)
    blr
}

#endif
