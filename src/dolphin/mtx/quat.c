#include "dolphin/math.h"
#include "dolphin/mtx.h"
#include "ffcc/symbols_shared.h"

float acosf(float x);

float sinf(float x);
float cosf(float x);

void C_QUATAdd(const Quaternion *p, const Quaternion *q, Qtrn *r)
{
    r->x = p->x + q->x;
    r->y = p->y + q->y;
    r->z = p->z + q->z;
    r->w = p->w + q->w;
}

void PSQUATAdd(register const Quaternion *p, register const Quaternion *q, register Quaternion *r)
{
    asm {
      psq_l f0, 0x0(r3), 0, 0
      psq_l f1, 0x0(r4), 0, 0
      ps_add f0, f0, f1
      psq_st f0, 0x0(r5), 0, 0
      psq_l f0, 0x8(r3), 0, 0
      psq_l f1, 0x8(r4), 0, 0
      ps_add f0, f0, f1
      psq_st f0, 0x8(r5), 0, 0
    }
}

void PSQUATMultiply(register const Quaternion *a, register const Quaternion *b, register Quaternion *ab)
{
    asm {
        psq_l f0, 0(a), 0, 0
        psq_l f1, 8(a), 0, 0
        psq_l f2, 0(b), 0, 0
        ps_neg f5, f0
        psq_l f3, 8(b), 0, 0
        ps_neg f6, f1
        ps_merge01 f4, f5, f0
        ps_muls0 f7, f1, f2
        ps_muls0 f5, f5, f2
        ps_merge01 f1, f6, f1
        ps_muls1 f8, f4, f2
        ps_madds0 f7, f4, f3, f7
        ps_muls1 f2, f1, f2
        ps_madds0 f5, f1, f3, f5
        ps_madds1 f8, f6, f3, f8
        ps_merge10 f7, f7, f7
        ps_madds1 f2, f0, f3, f2
        ps_merge10 f5, f5, f5
        ps_add f7, f7, f2
        psq_st f7, 0(ab), 0, 0
        ps_sub f5, f5, f8
        psq_st f5, 8(ab), 0, 0
    }
}

void PSQUATNormalize(const register Quaternion *src, register Quaternion *unit)
{
    {
        register f32 vv1, vv2, vv3;
        register f32 vv4, vv5, vv6;
        register f32 vv7, vv8;
        register f32 vv9 = kQuatNormalizeEpsilon;
        register f32 vvA = kQuatHalf;
        register f32 vvB = kQuatNormalizeThree;
        asm
        {
            psq_l    vv1, 0(src), 0, 0;
            ps_mul   vv3, vv1, vv1;
            psq_l    vv2, 8(src), 0, 0;
            ps_sub   vv6, vv9, vv9;
            ps_madd  vv3, vv2, vv2, vv3;
            ps_sum0  vv3, vv3, vv3, vv3;
            frsqrte  vv4, vv3;
            ps_sub   vv5, vv3, vv9;
            fmul     vv7, vv4, vv4;
            fmul     vv8, vv4, vvA;
            fnmsub   vv7, vv7, vv3, vvB;
            fmul     vv4, vv7, vv8;
            ps_sel   vv4, vv5, vv4, vv6;
            ps_muls0 vv1, vv1, vv4;
            ps_muls0 vv2, vv2, vv4;
            psq_st   vv1, 0(unit), 0, 0;
            psq_st   vv2, 8(unit), 0, 0;
        }
    }
}

void PSQUATInverse(const register Quaternion *src, register Quaternion *inv)
{
    register f32 vv1, vv2, vv3, vv4;
    register f32 vv5, vv6, vv7, vv8, vv9, vvA, vvB;
    register f32 vvC = 1.0F;
    asm {
        psq_l       vv1, 0(src), 0, 0;
        ps_mul      vv5, vv1, vv1;
        psq_l       vv2, 8(src), 0, 0;
        ps_madd     vv5, vv2, vv2, vv5;
        ps_add      vvA, vvC, vvC;
        ps_sum0     vv5, vv5, vv5, vv5;
        fres        vv7, vv5;
        ps_neg      vv6, vv5;
        ps_nmsub    vv9, vv5, vv7, vvA;
        ps_mul      vv7, vv7, vv9;
        ps_sel vv7, vv6, vvC, vv7
        b           loc1;
    loc0:
        fmr         vv7, vvC;
    loc1:
        ps_neg      vv8, vv7;
        ps_muls1    vv4, vv7, vv2;
        ps_muls0    vv1, vv1, vv8;
        psq_st      vv4, 12(inv), 1, 0;
        ps_muls0    vv3, vv2, vv8;
        psq_st      vv1, 0(inv), 0, 0;
        psq_st      vv3, 8(inv), 1, 0;
    }
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void C_QUATRotAxisRad(Quaternion *q, const Vec *axis, f32 rad)
{
    f32 tmp, tmp2, tmp3;
    Vec dst;

    tmp = rad;
    PSVECNormalize(axis, &dst);

    tmp2 = kQuatHalf * tmp;
    tmp3 = sinf(kQuatHalf * tmp);
    tmp = tmp3;
    tmp3 = cosf(tmp2);

    q->x = tmp * dst.x;
    q->y = tmp * dst.y;
    q->z = tmp * dst.z;
    q->w = tmp3;
}

#pragma fp_contract off
void C_QUATMtx(Quaternion *r, const Mtx m)
{
    f32 vv0, vv1;
    s32 i, j, k;
    s32 idx[3] = { 1, 2, 0 };
    f32 vec[3];
    vv0 = m[0][0] + m[1][1] + m[2][2];
    if (vv0 > 0.0f) {
        vv1 = (f32)sqrtf(vv0 + 1.0f);
        r->w = vv1 * 0.5f;
        vv1 = 0.5f / vv1;
        r->x = (m[2][1] - m[1][2]) * vv1;
        r->y = (m[0][2] - m[2][0]) * vv1;
        r->z = (m[1][0] - m[0][1]) * vv1;
    }
    else {
        i = 0;
        if (m[1][1] > m[0][0])
            i = 1;
        if (m[2][2] > m[i][i])
            i = 2;
        j = idx[i];
        k = idx[j];
        vv1 = (f32)sqrtf((m[i][i] - (m[j][j] + m[k][k])) + 1.0f);
        vec[i] = vv1 * 0.5f;
        if (vv1 != 0.0f)
            vv1 = 0.5f / vv1;
        r->w = (m[k][j] - m[j][k]) * vv1;
        vec[j] = (m[i][j] + m[j][i]) * vv1;
        vec[k] = (m[i][k] + m[k][i]) * vv1;
        r->x = vec[0];
        r->y = vec[1];
        r->z = vec[2];
    }
}
#pragma fp_contract on

void C_QUATLerp(const Quaternion *p, const Quaternion *q, Quaternion *r, f32 t)
{
    f32 value;
    f32 pValue;

    pValue = p->x;
    value = t * (q->x - pValue);
    r->x = pValue + value;

    pValue = p->y;
    value = t * (q->y - pValue);
    r->y = pValue + value;

    pValue = p->z;
    value = t * (q->z - pValue);
    r->z = pValue + value;

    value = t * (q->w - p->w);
    r->w = p->w + value;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
#pragma fp_contract off
void C_QUATSlerp(const Quaternion *p, const Quaternion *q, Quaternion *r, f32 t)
{
    f32 theta, sin_th, cos_th;
    f32 tp, tq;

    cos_th = p->x * q->x + p->y * q->y + p->z * q->z + p->w * q->w;
    tq = 1.0f;

    if (cos_th < 0.0f) {
        cos_th = -cos_th;
        tq = -tq;
    }

    if (cos_th <= 0.99999f) {
        theta = acosf(cos_th);
        sin_th = sinf(theta);

        tp = sinf((1.0f - t) * theta) / sin_th;
        tq *= sinf(t * theta) / sin_th;
    } else {
        tp = 1.0f - t;
        tq *= t;
    }

    r->x = (tp * p->x) + (tq * q->x);
    r->y = (tp * p->y) + (tq * q->y);
    r->z = (tp * p->z) + (tq * q->z);
    r->w = (tp * p->w) + (tq * q->w);
}
#pragma fp_contract on
