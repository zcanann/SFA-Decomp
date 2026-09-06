#include "dolphin/mtx.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math.h"

static f32 Unit01[] = {0.0f, 1.0f};


#define Mtx_00                  0x0
#define Mtx_01                  0x4
#define Mtx_02                  0x8
#define Mtx_03                  0xc
#define Mtx_10                  0x10
#define Mtx_11                  0x14
#define Mtx_12                  0x18
#define Mtx_13                  0x1c
#define Mtx_20                  0x20
#define Mtx_21                  0x24
#define Mtx_22                  0x28
#define Mtx_23                  0x2c
#define qr0                     0

void C_MTXIdentity(Mtx m)
{
  m[0][0] = 1.0f;
  m[0][1] = 0.0f;
  m[0][2] = 0.0f;
  m[0][3] = 0.0f;

  m[1][0] = 0.0f;
  m[1][1] = 1.0f;
  m[1][2] = 0.0f;
  m[1][3] = 0.0f;

  m[2][0] = 0.0f;
  m[2][1] = 0.0f;
  m[2][2] = 1.0f;
  m[2][3] = 0.0f;
}

#ifdef GEKKO
void PSMTXIdentity(register Mtx m) {
    register f32 c_zero = 0.0f;
    register f32 c_one = 1.0f;
    register f32 c_01;
    register f32 c_10;

    asm {
        psq_st c_zero, Mtx_02(m), 0, qr0
        ps_merge01 c_01, c_zero, c_one
        psq_st c_zero, Mtx_12(m), 0, qr0
        ps_merge10 c_10, c_one, c_zero
        psq_st c_zero, Mtx_20(m), 0, qr0
        psq_st c_01, Mtx_10(m), 0, qr0
        psq_st c_10, Mtx_00(m), 0, qr0
        psq_st c_10, Mtx_22(m), 0, qr0
    }
}

// clang-format off
asm void PSMTXCopy(const register Mtx src, register Mtx dst)
{
    nofralloc
    psq_l f0, Mtx_00(src), 0, qr0
    psq_st f0, Mtx_00(dst), 0, qr0
    psq_l f1, Mtx_02(src), 0, qr0
    psq_st f1, Mtx_02(dst), 0, qr0
    psq_l f2, Mtx_10(src), 0, qr0
    psq_st f2, Mtx_10(dst), 0, qr0
    psq_l f3, Mtx_12(src), 0, qr0
    psq_st f3, Mtx_12(dst), 0, qr0
    psq_l f4, Mtx_20(src), 0, qr0
    psq_st f4, Mtx_20(dst), 0, qr0
    psq_l f5, Mtx_22(src), 0, qr0
    psq_st f5, Mtx_22(dst), 0, qr0
    blr
}
// clang-format on

// clang-format off
asm void PSMTXConcat(const register Mtx mA, const register Mtx mB, register Mtx mAB)
{
    nofralloc
    stwu    sp, -64(sp)
    psq_l   fp0, Mtx_00(mA), 0, qr0
    stfd    fp14, 8(sp)
    psq_l   fp6, Mtx_00(mB), 0, qr0
    lis     r6, Unit01@ha
    psq_l   fp7, Mtx_02(mB), 0, qr0
    stfd    fp15, 16(sp)
    addi    r6, r6, Unit01@l
    stfd    fp31, 40(sp)
    psq_l   fp8, Mtx_10(mB), 0, qr0
    ps_muls0 fp12, fp6, fp0
    psq_l   fp2, Mtx_10(mA), 0, qr0
    ps_muls0 fp13, fp7, fp0
    psq_l   fp31, 0(r6), 0, qr0
    ps_muls0 fp14, fp6, fp2
    psq_l   fp9, Mtx_12(mB), 0, qr0
    ps_muls0 fp15, fp7, fp2
    psq_l   fp1, Mtx_02(mA), 0, qr0
    ps_madds1 fp12, fp8, fp0, fp12
    psq_l   fp3, Mtx_12(mA), 0, qr0
    ps_madds1 fp14, fp8, fp2, fp14
    psq_l   fp10, Mtx_20(mB), 0, qr0
    ps_madds1 fp13, fp9, fp0, fp13
    psq_l   fp11, Mtx_22(mB), 0, qr0
    ps_madds1 fp15, fp9, fp2, fp15
    psq_l   fp4, Mtx_20(mA), 0, qr0
    psq_l   fp5, Mtx_22(mA), 0, qr0
    ps_madds0 fp12, fp10, fp1, fp12
    ps_madds0 fp13, fp11, fp1, fp13
    ps_madds0 fp14, fp10, fp3, fp14
    ps_madds0 fp15, fp11, fp3, fp15
    psq_st  fp12, Mtx_00(mAB), 0, qr0
    ps_muls0 fp2, fp6, fp4
    ps_madds1 fp13, fp31, fp1, fp13
    ps_muls0 fp0, fp7, fp4
    psq_st  fp14, Mtx_10(mAB), 0, qr0
    ps_madds1 fp15, fp31, fp3, fp15
    psq_st  fp13, Mtx_02(mAB), 0, qr0
    ps_madds1 fp2, fp8, fp4, fp2
    ps_madds1 fp0, fp9, fp4, fp0
    ps_madds0 fp2, fp10, fp5, fp2
    lfd    fp14, 8(sp)
    psq_st  fp15, Mtx_12(mAB), 0, qr0
    ps_madds0 fp0, fp11, fp5, fp0
    psq_st  fp2, Mtx_20(mAB), 0, qr0
    ps_madds1 fp0, fp31, fp5, fp0
    lfd    fp15, 16(sp)
    psq_st  fp0, Mtx_22(mAB), 0, qr0
    lfd    fp31, 40(sp)
    addi   sp, sp, 64
    blr
}
// clang-format on

void PSMTXTranspose(const register Mtx src, register Mtx xPose) {
    register f32 c_zero = 0.0f;
    register f32 row0a;
    register f32 row1a;
    register f32 row0b;
    register f32 row1b;
    register f32 trns0;
    register f32 trns1;
    register f32 trns2;

    asm {
        psq_l row0a, Mtx_00(src), 0, qr0
        stfs c_zero, Mtx_23(xPose)
        psq_l row1a, Mtx_10(src), 0, qr0
        ps_merge00 trns0, row0a, row1a
        psq_l row0b, Mtx_02(src), 1, qr0
        ps_merge11 trns1, row0a, row1a
        psq_l row1b, Mtx_12(src), 1, qr0
        psq_st trns0, Mtx_00(xPose), 0, qr0
        psq_l row0a, Mtx_20(src), 0, qr0
        ps_merge00 trns2, row0b, row1b
        psq_st trns1, Mtx_10(xPose), 0, qr0
        ps_merge00 trns0, row0a, c_zero
        psq_st trns2, Mtx_20(xPose), 0, qr0
        ps_merge10 trns1, row0a, c_zero
        psq_st trns0, Mtx_02(xPose), 0, qr0
        lfs row0b, Mtx_22(src)
        psq_st trns1, Mtx_12(xPose), 0, qr0
        stfs row0b, Mtx_22(xPose)
    }
}

// clang-format off
asm u32 PSMTXInverse(const register Mtx src, register Mtx inv)
{
    nofralloc
    psq_l       fp0, Mtx_00(src), 1, qr0
    psq_l       fp1, Mtx_01(src), 0, qr0
    psq_l       fp2, Mtx_10(src), 1, qr0
    ps_merge10  fp6, fp1, fp0
    psq_l       fp3, Mtx_11(src), 0, qr0
    psq_l       fp4, Mtx_20(src), 1, qr0
    ps_merge10  fp7, fp3, fp2
    psq_l       fp5, Mtx_21(src), 0, qr0
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
    li          r3, 0
    blr
_regular:
    fres        fp0, fp7
    ps_add      fp6, fp0, fp0
    ps_mul      fp5, fp0, fp0
    ps_nmsub    fp0, fp7, fp5, fp6
    lfs         fp1, Mtx_03(src)
    ps_muls0    fp13, fp13, fp0
    lfs         fp2, Mtx_13(src)
    ps_muls0    fp12, fp12, fp0
    lfs         fp3, Mtx_23(src)
    ps_muls0    fp11, fp11, fp0
    ps_merge00  fp5, fp13, fp12
    ps_muls0    fp10, fp10, fp0
    ps_merge11  fp4, fp13, fp12
    ps_muls0    fp9,  fp9,  fp0
    psq_st      fp5,  Mtx_00(inv), 0, qr0
    ps_mul      fp6, fp13, fp1
    psq_st      fp4,  Mtx_10(inv), 0, qr0
    ps_muls0    fp8,  fp8,  fp0
    ps_madd     fp6, fp12, fp2, fp6
    psq_st      fp10, Mtx_20(inv), 1, qr0
    ps_nmadd    fp6, fp11, fp3, fp6
    psq_st      fp9,  Mtx_21(inv), 1, qr0
    ps_mul      fp7, fp10, fp1
    ps_merge00  fp5, fp11, fp6
    psq_st      fp8,  Mtx_22(inv), 1, qr0
    ps_merge11  fp4, fp11, fp6
    psq_st      fp5,  Mtx_02(inv), 0, qr0
    ps_madd     fp7, fp9,  fp2, fp7
    psq_st      fp4,  Mtx_12(inv), 0, qr0
    ps_nmadd    fp7, fp8,  fp3, fp7
    li          r3, 1
    psq_st      fp7,  Mtx_23(inv), 1, qr0
    blr
}

void PSMTXRotRad(Mtx m, char axis, f32 rad)
{
    f32 sinA, cosA;

    sinA = sinf(rad);
    cosA = cosf(rad);

    PSMTXRotTrig(m, axis, sinA, cosA);
}
// clang-format on

void PSMTXRotTrig(register Mtx m, register char axis, register f32 sinA, register f32 cosA) {
    register f32 fc0 = 0.0f;
    register f32 fc1 = 1.0f;
    register f32 nsinA;
    register f32 fw0;
    register f32 fw1;
    register f32 fw2;
    register f32 fw3;

    asm {
        ori axis, axis, 0x20
        ps_neg nsinA, sinA
        cmplwi axis, 'x'
        beq axis_x
        cmplwi axis, 'y'
        beq axis_y
        cmplwi axis, 'z'
        beq axis_z
        b epilogue
    axis_x:
        psq_st fc1, Mtx_00(m), 1, qr0
        psq_st fc0, Mtx_01(m), 0, qr0
        ps_merge00 fw0, sinA, cosA
        psq_st fc0, Mtx_03(m), 0, qr0
        ps_merge00 fw1, cosA, nsinA
        psq_st fc0, Mtx_13(m), 0, qr0
        psq_st fc0, Mtx_23(m), 1, qr0
        psq_st fw0, Mtx_21(m), 0, qr0
        psq_st fw1, Mtx_11(m), 0, qr0
        b epilogue
    axis_y:
        ps_merge00 fw0, cosA, fc0
        ps_merge00 fw1, fc0, fc1
        psq_st fc0, Mtx_12(m), 0, qr0
        psq_st fw0, Mtx_00(m), 0, qr0
        ps_merge00 fw2, nsinA, fc0
        ps_merge00 fw3, sinA, fc0
        psq_st fw0, Mtx_22(m), 0, qr0
        psq_st fw1, Mtx_10(m), 0, qr0
        psq_st fw3, Mtx_02(m), 0, qr0
        psq_st fw2, Mtx_20(m), 0, qr0
        b epilogue
    axis_z:
        psq_st fc0, Mtx_02(m), 0, qr0
        ps_merge00 fw0, sinA, cosA
        ps_merge00 fw2, cosA, nsinA
        psq_st fc0, Mtx_12(m), 0, qr0
        psq_st fc0, Mtx_20(m), 0, qr0
        ps_merge00 fw1, fc1, fc0
        psq_st fw0, Mtx_10(m), 0, qr0
        psq_st fw2, Mtx_00(m), 0, qr0
        psq_st fw1, Mtx_22(m), 0, qr0
    epilogue:
    }
}

// clang-format off
void PSMTXRotAxisRad(register Mtx m, const Vec *axis, register f32 rad)
{
    register f32 tmp0, tmp1, tmp2, tmp3, tmp4;
    register f32 tmp5, tmp6, tmp7, tmp8, tmp9;

    register f32 sT;
    register f32 cT;
    register f32 oneMinusCosT;
    register f32 zero;
    Vec axisNormalized;
    register Vec *axisNormalizedPtr;

    zero = 0.0f;
    axisNormalizedPtr = &axisNormalized;
    sT = sinf(rad);
    cT = cosf(rad);
    oneMinusCosT = 1.0f - cT;

    PSVECNormalize(axis, axisNormalizedPtr);

#ifdef __MWERKS__ // clang-format off
  asm {
		psq_l rad, 0x0(axisNormalizedPtr), 0, qr0
		lfs tmp1, 0x8(axisNormalizedPtr)
		ps_merge00 tmp0, cT, cT
		ps_muls0   tmp4, rad, oneMinusCosT
		ps_muls0   tmp5, tmp1, oneMinusCosT
		ps_muls1   tmp3, tmp4, rad
		ps_muls0   tmp2, tmp4, rad
		ps_muls0   rad, rad, sT
		ps_muls0   tmp4, tmp4, tmp1
		fnmsubs    tmp6, tmp1, sT, tmp3
		fmadds     tmp7, tmp1, sT, tmp3
		ps_neg     tmp9, rad
		ps_sum0    tmp8, tmp4, zero, rad
		ps_sum0    tmp2, tmp2, tmp6, tmp0
		ps_sum1    tmp3, tmp0, tmp7, tmp3
		ps_sum0    tmp6, tmp9, zero, tmp4
		ps_sum0    tmp9, tmp4, tmp4, tmp9
		psq_st     tmp8, 0x8(m), 0, qr0
		ps_muls0   tmp5, tmp5, tmp1
		psq_st     tmp2, 0x0(m), 0, qr0
		ps_sum1    tmp4, rad, tmp9, tmp4
		psq_st     tmp3, 0x10(m), 0, qr0
		ps_sum0    tmp5, tmp5, zero, tmp0
		psq_st     tmp6, 0x18(m), 0, qr0
		psq_st     tmp4, 0x20(m), 0, qr0
		psq_st     tmp5, 0x28(m), 0, qr0
  }
#endif // clang-format on
}
// clang-format on

void PSMTXTrans(register Mtx m, register f32 xT, register f32 yT, register f32 zT) {
    register f32 c0 = 0.0f;
    register f32 c1 = 1.0f;

    asm {
        stfs xT, Mtx_03(m)
        stfs yT, Mtx_13(m)
        psq_st c0, Mtx_01(m), 0, qr0
        psq_st c0, Mtx_20(m), 0, qr0
        stfs c0, Mtx_10(m)
        stfs c1, Mtx_11(m)
        stfs c0, Mtx_12(m)
        stfs c1, Mtx_22(m)
        stfs zT, Mtx_23(m)
        stfs c1, Mtx_00(m)
    }
}

void PSMTXScale(register Mtx m, register f32 xS, register f32 yS, register f32 zS) {
    register f32 c0 = 0.0f;

    asm {
        stfs xS, Mtx_00(m)
        psq_st c0, Mtx_01(m), 0, qr0
        psq_st c0, Mtx_03(m), 0, qr0
        stfs yS, Mtx_11(m)
        psq_st c0, Mtx_12(m), 0, qr0
        psq_st c0, Mtx_20(m), 0, qr0
        stfs zS, Mtx_22(m)
        stfs c0, Mtx_23(m)
    }
}

// clang-format off
void C_MTXLightFrustum(Mtx m, f32 t, f32 b, f32 l, f32 r, f32 n, f32 scaleS, f32 scaleT, f32 transS, f32 transT)
{
    f32 tmp;

    tmp = 1.0f / (r - l);
    m[0][0] = ((2.0f * n) * tmp) * scaleS;
    m[0][1] = 0.0f;
    m[0][2] = (((r + l) * tmp) * scaleS) - transS;
    m[0][3] = 0.0f;

    tmp = 1.0f / (t - b);
    m[1][0] = 0.0f;
    m[1][1] = ((2.0f * n) * tmp) * scaleT;
    m[1][2] = (((t + b) * tmp) * scaleT) - transT;
    m[1][3] = 0.0f;

    m[2][0] = 0.0f;
    m[2][1] = 0.0f;
    m[2][2] = -1.0f;
    m[2][3] = 0.0f;
}

void C_MTXLightPerspective(Mtx m, f32 fovY, f32 aspect, float scaleS, float scaleT, float transS, float transT)
{
    f32 angle;
    f32 cot;

    angle = fovY * 0.5f;
    angle = MTXDegToRad(angle);

    cot = 1.0f / tanf(angle);

    m[0][0] = (cot / aspect) * scaleS;
    m[0][1] = 0.0f;
    m[0][2] = -transS;
    m[0][3] = 0.0f;

    m[1][0] = 0.0f;
    m[1][1] = cot * scaleT;
    m[1][2] = -transT;
    m[1][3] = 0.0f;

    m[2][0] = 0.0f;
    m[2][1] = 0.0f;
    m[2][2] = -1.0f;
    m[2][3] = 0.0f;
}

void C_MTXLightOrtho(Mtx m, f32 t, f32 b, f32 l, f32 r, float scaleS, float scaleT, float transS, float transT)
{
    f32 tmp;
    tmp = 1.0f / (r - l);
    m[0][0] = (2.0f * tmp * scaleS);
    m[0][1] = 0.0f;
    m[0][2] = 0.0f;
    m[0][3] = ((-(r + l) * tmp) * scaleS) + transS;

    tmp = 1.0f / (t - b);
    m[1][0] = 0.0f;
    m[1][1] = (2.0f * tmp) * scaleT;
    m[1][2] = 0.0f;
    m[1][3] = ((-(t + b) * tmp) * scaleT) + transT;

    m[2][0] = 0.0f;
    m[2][1] = 0.0f;
    m[2][2] = 0.0f;
    m[2][3] = 1.0f;
}
// clang-format on

#endif
