#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

#pragma fp_contract off

extern GXData* gx;
#define __GXData gx

const f32 lbl_803E8318 = 0.0f;
const f32 lbl_803E831C = 90.0f;
const f32 lbl_803E8320 = 3.1415927f;
const f32 lbl_803E8324 = 180.0f;
const f32 lbl_803E8328 = -1000.0f;
const f32 lbl_803E832C = 1000.0f;
const f32 lbl_803E8330 = 1.0f;
const f32 lbl_803E8334 = 2.0f;
const f32 lbl_803E8338 = -1.0f;
const f32 lbl_803E833C = -4.0f;
const f32 lbl_803E8340 = 4.0f;
const f32 lbl_803E8344 = -2.0f;
const f32 lbl_803E8348 = 0.5f;
const double lbl_803E8350 = 0.5;
const double lbl_803E8358 = 3.0;
const f32 lbl_803E8360[2] = {1048576.0f, 0.0f};

extern f32 cosf(f32);

static inline float sqrtf(float x) {
    static const double half = 0.5;
    static const double three = 3.0;
    volatile float y;

    if (x > 0.0f) {
        double guess = __frsqrte((double)x);
        guess = half * guess * (three - guess * guess * x);
        guess = half * guess * (three - guess * guess * x);
        guess = half * guess * (three - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }

    return x;
}

// GXLightObj private data
typedef struct {
    u32 reserved[3];
    u32 Color;
    f32 a[3];
    f32 k[3];
    f32 lpos[3];
    f32 ldir[3];
} __GXLightObjInt_struct;

void GXInitLightAttn(GXLightObj* lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(129, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(130, "GXInitLightAttn");
    obj->a[0] = a0;
    obj->a[1] = a1;
    obj->a[2] = a2;
    obj->k[0] = k0;
    obj->k[1] = k1;
    obj->k[2] = k2;
}

void GXInitLightAttnA(GXLightObj* lt_obj, f32 a0, f32 a1, f32 a2) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(143, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(144, "GXInitLightAttnA");
    obj->a[0] = a0;
    obj->a[1] = a1;
    obj->a[2] = a2;
}

void GXInitLightAttnK(GXLightObj* lt_obj, f32 k0, f32 k1, f32 k2) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(163, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(164, "GXInitLightAttnK");
    obj->k[0] = k0;
    obj->k[1] = k1;
    obj->k[2] = k2;
}

void GXGetLightAttnK(const GXLightObj* lt_obj, f32* k0, f32* k1, f32* k2) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(173, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(174, "GXGetLightAttnK");
    *k0 = obj->k[0];
    *k1 = obj->k[1];
    *k2 = obj->k[2];
}

void GXInitLightSpot(GXLightObj* lt_obj, f32 cutoff, GXSpotFn spot_func) {
    f32 cr;
    f32 d;
    f32 a0, a1, a2;
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(198, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(200, "GXInitLightSpot");

    if (cutoff <= 0.0f || cutoff > 90.0f)
        spot_func = GX_SP_OFF;

    cr = cosf((3.1415927f * cutoff) / 180.0f);

    switch (spot_func) {
    case GX_SP_FLAT:
        a0 = -1000.0f * cr;
        a1 = 1000.0f;
        a2 = 0.0f;
        break;
    case GX_SP_COS:
        a2 = 0.0f;
        a0 = -cr / (1.0f - cr);
        a1 = 1.0f / (1.0f - cr);
        break;
    case GX_SP_COS2:
        a0 = 0.0f;
        a1 = -cr / (1.0f - cr);
        a2 = 1.0f / (1.0f - cr);
        break;
    case GX_SP_SHARP: {
        f32 u = 1.0f - cr;
        d = u * u;
        a1 = 2.0f / d;
        a0 = (cr * (cr - 2.0f)) / d;
        a2 = lbl_803E8338 / d;
        break;
    }
    case GX_SP_RING1: {
        f32 u = 1.0f - cr;
        d = u * u;
        a0 = (lbl_803E833C * cr) / d;
        a1 = (lbl_803E8340 * (1.0f + cr)) / d;
        a2 = lbl_803E833C / d;
        break;
    }
    case GX_SP_RING2: {
        f32 u = 1.0f - cr;
        f32 two_cr = lbl_803E8334 * cr;
        d = u * u;
        a0 = 1.0f - (two_cr * cr) / d;
        a1 = (lbl_803E8340 * cr) / d;
        a2 = lbl_803E8344 / d;
        break;
    }
    case GX_SP_OFF:
    default:
        a0 = 1.0f;
        a1 = 0.0f;
        a2 = 0.0f;
        break;
    }
    obj->a[0] = a0;
    obj->a[1] = a1;
    obj->a[2] = a2;
}

void GXInitLightDistAttn(GXLightObj* lt_obj, f32 ref_dist, f32 ref_br, GXDistAttnFn dist_func) {
    f32 k0, k1, k2;
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(273, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(275, "GXInitLightDistAttn");

    if (ref_dist < 0.0f)
        dist_func = GX_DA_OFF;
    if (ref_br <= 0.0f || ref_br >= 1.0f)
        dist_func = GX_DA_OFF;

    switch (dist_func) {
    case GX_DA_GENTLE:
        k0 = 1.0f;
        k1 = (1.0f - ref_br) / (ref_br * ref_dist);
        k2 = 0.0f;
        break;
    case GX_DA_MEDIUM:
        k0 = 1.0f;
        k1 = 0.5f * (1.0f - ref_br) / (ref_br * ref_dist);
        k2 = 0.5f * (1.0f - ref_br) / (ref_br * ref_dist * ref_dist);
        break;
    case GX_DA_STEEP:
        k0 = 1.0f;
        k1 = 0.0f;
        k2 = (1.0f - ref_br) / (ref_br * ref_dist * ref_dist);
        break;
    case GX_DA_OFF:
    default:
        k0 = 1.0f;
        k1 = 0.0f;
        k2 = 0.0f;
        break;
    }

    obj->k[0] = k0;
    obj->k[1] = k1;
    obj->k[2] = k2;
}

void GXInitLightPos(GXLightObj* lt_obj, f32 x, f32 y, f32 z) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(328, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(330, "GXInitLightPos");

    obj->lpos[0] = x;
    obj->lpos[1] = y;
    obj->lpos[2] = z;
}

void GXInitLightDir(GXLightObj* lt_obj, f32 nx, f32 ny, f32 nz) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(360, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;

    obj->ldir[0] = -nx;
    obj->ldir[1] = -ny;
    obj->ldir[2] = -nz;
}

void GXInitSpecularDir(GXLightObj* lt_obj, f32 nx, f32 ny, f32 nz) {
    f32 mag;
    f32 vx;
    f32 vy;
    f32 vz;
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(398, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(399, "GXInitSpecularDir");

    vx = -nx;
    vy = -ny;
    vz = 1.0f - nz;

    mag = 1.0f / sqrtf((vx * vx) + (vy * vy) + (vz * vz));

    obj->ldir[0] = vx * mag;
    obj->ldir[1] = vy * mag;
    obj->ldir[2] = vz * mag;
    obj->lpos[0] = vx * 1048576.0f;
    obj->lpos[1] = vy * 1048576.0f;
    obj->lpos[2] = -nz * 1048576.0f;
}

void GXInitLightColor(GXLightObj* lt_obj, GXColor color) {
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(462, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(463, "GXInitLightColor");

    obj->Color = ((u32)color.r << 24) | ((u32)color.g << 16) | ((u32)color.b << 8) | (u32)color.a;
}

#if DEBUG
#define WRITE_SOME_LIGHT_REG1(val, addr) \
do {  \
    u32 xfData = val; \
    GX_WRITE_U32(val); \
    VERIF_MTXLIGHT(addr, xfData); \
} while (0)

#define WRITE_SOME_LIGHT_REG2(val, addr) \
do {  \
    f32 xfData = val; \
    GX_WRITE_F32(val); \
    VERIF_MTXLIGHT(addr, *(u32*)&xfData); \
} while (0)
#else
#define WRITE_SOME_LIGHT_REG1(val, addr) GX_WRITE_U32(val)
#define WRITE_SOME_LIGHT_REG2(val, addr) GX_WRITE_F32(val)
#endif

static inline u32 ConvLightID2Num(GXLightID id) {
    switch (id) {
    case GX_LIGHT0: return 0;
    case GX_LIGHT1: return 1;
    case GX_LIGHT2: return 2;
    case GX_LIGHT3: return 3;
    case GX_LIGHT4: return 4;
    case GX_LIGHT5: return 5;
    case GX_LIGHT6: return 6;
    case GX_LIGHT7: return 7;
    default:        return 0;
    }
}

static inline void PushLight(const register GXLightObj* lt_obj, register void* dest) {
    register u32 zero, color;
    register f32 a0_a1, a2_k0, k1_k2;
    register f32 px_py, pz_dx, dy_dz;
#ifdef __MWERKS__  // clang-format off
	asm {
		lwz     color, 12(lt_obj)
		xor     zero, zero, zero
		psq_l   a0_a1, 16(lt_obj), 0, 0
		psq_l   a2_k0, 24(lt_obj), 0, 0
		psq_l   k1_k2, 32(lt_obj), 0, 0
		psq_l   px_py, 40(lt_obj), 0, 0
		psq_l   pz_dx, 48(lt_obj), 0, 0
		psq_l   dy_dz, 56(lt_obj), 0, 0

		stw     zero,  0(dest)
		stw     zero,  0(dest)
		stw     zero,  0(dest)
		stw     color, 0(dest)
		psq_st  a0_a1, 0(dest), 0, 0
		psq_st  a2_k0, 0(dest), 0, 0
		psq_st  k1_k2, 0(dest), 0, 0
		psq_st  px_py, 0(dest), 0, 0
		psq_st  pz_dx, 0(dest), 0, 0
		psq_st  dy_dz, 0(dest), 0, 0
	}
#endif  // clang-format on
}

void GXLoadLightObjImm(const GXLightObj* lt_obj, GXLightID light) {
    u32 addr;
    u32 idx;
    __GXLightObjInt_struct* obj;

    ASSERTMSGLINE(568, lt_obj != NULL, "Light Object Pointer is null");
    obj = (__GXLightObjInt_struct*)lt_obj;
    CHECK_GXBEGIN(569, "GXLoadLightObjImm");

    idx = ConvLightID2Num(light);

    ASSERTMSGLINE(575, idx < 8, "GXLoadLightObjImm: Invalid Light Id");

    addr = idx * 0x10 + 0x600;
    GX_WRITE_U8(0x10);
    GX_WRITE_U32(addr | 0xF0000);

    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(0);
    GX_WRITE_U32(obj->Color);
    GX_WRITE_F32(obj->a[0]);
    GX_WRITE_F32(obj->a[1]);
    GX_WRITE_F32(obj->a[2]);
    GX_WRITE_F32(obj->k[0]);
    GX_WRITE_F32(obj->k[1]);
    GX_WRITE_F32(obj->k[2]);
    GX_WRITE_F32(obj->lpos[0]);
    GX_WRITE_F32(obj->lpos[1]);
    GX_WRITE_F32(obj->lpos[2]);
    GX_WRITE_F32(obj->ldir[0]);
    GX_WRITE_F32(obj->ldir[1]);
    GX_WRITE_F32(obj->ldir[2]);

    __GXData->bpSentNot = 1;
}

#define GXCOLOR_AS_U32(color) (*((u32*)&(color)))

void GXSetChanAmbColor(GXChannelID chan, GXColor amb_color) {
    u32 reg;
    u32 colIdx;

    CHECK_GXBEGIN(661, "GXSetChanAmbColor");

    switch (chan) {
    case GX_COLOR0:
        reg = __GXData->ambColor[GX_COLOR0] & 0xFF;
        SET_REG_FIELD(0, reg, 8, 8, amb_color.b);
        SET_REG_FIELD(0, reg, 8, 16, amb_color.g);
        SET_REG_FIELD(0, reg, 8, 24, amb_color.r);
        colIdx = 0;
        break;
    case GX_COLOR1:
        reg = __GXData->ambColor[GX_COLOR1] & 0xFF;
        SET_REG_FIELD(0, reg, 8, 8, amb_color.b);
        SET_REG_FIELD(0, reg, 8, 16, amb_color.g);
        SET_REG_FIELD(0, reg, 8, 24, amb_color.r);
        colIdx = 1;
        break;
    case GX_ALPHA0:
        reg = (__GXData->ambColor[GX_COLOR0] & ~0xFF) | amb_color.a;
        colIdx = 0;
        break;
    case GX_ALPHA1:
        reg = (__GXData->ambColor[GX_COLOR1] & ~0xFF) | amb_color.a;
        colIdx = 1;
        break;
    case GX_COLOR0A0:
        reg = amb_color.a;
        SET_REG_FIELD(0, reg, 8, 8, amb_color.b);
        SET_REG_FIELD(0, reg, 8, 16, amb_color.g);
        SET_REG_FIELD(0, reg, 8, 24, amb_color.r);
        colIdx = 0;
        break;
    case GX_COLOR1A1:
        reg = amb_color.a;
        SET_REG_FIELD(0, reg, 8, 8, amb_color.b);
        SET_REG_FIELD(0, reg, 8, 16, amb_color.g);
        SET_REG_FIELD(0, reg, 8, 24, amb_color.r);
        colIdx = 1;
        break;
    default:
        ASSERTMSGLINE(731, 0, "GXSetChanAmbColor: Invalid Channel Id");
        return;
    }

    GX_WRITE_XF_REG(colIdx + 10, reg);
    __GXData->bpSentNot = 1;
    __GXData->ambColor[colIdx] = reg;
}

void GXSetChanMatColor(GXChannelID chan, GXColor mat_color) {
    u32 reg;
    u32 colIdx;

    CHECK_GXBEGIN(762, "GXSetChanMatColor");

    switch (chan) {
    case GX_COLOR0:
        reg = __GXData->matColor[GX_COLOR0] & 0xFF;
        SET_REG_FIELD(0, reg, 8, 8, mat_color.b);
        SET_REG_FIELD(0, reg, 8, 16, mat_color.g);
        SET_REG_FIELD(0, reg, 8, 24, mat_color.r);
        colIdx = 0;
        break;
    case GX_COLOR1:
        reg = __GXData->matColor[GX_COLOR1] & 0xFF;
        SET_REG_FIELD(0, reg, 8, 8, mat_color.b);
        SET_REG_FIELD(0, reg, 8, 16, mat_color.g);
        SET_REG_FIELD(0, reg, 8, 24, mat_color.r);
        colIdx = 1;
        break;
    case GX_ALPHA0:
        reg = (__GXData->matColor[GX_COLOR0] & ~0xFF) | mat_color.a;
        colIdx = 0;
        break;
    case GX_ALPHA1:
        reg = (__GXData->matColor[GX_COLOR1] & ~0xFF) | mat_color.a;
        colIdx = 1;
        break;
    case GX_COLOR0A0:
        reg = mat_color.a;
        SET_REG_FIELD(0, reg, 8, 8, mat_color.b);
        SET_REG_FIELD(0, reg, 8, 16, mat_color.g);
        SET_REG_FIELD(0, reg, 8, 24, mat_color.r);
        colIdx = 0;
        break;
    case GX_COLOR1A1:
        reg = mat_color.a;
        SET_REG_FIELD(0, reg, 8, 8, mat_color.b);
        SET_REG_FIELD(0, reg, 8, 16, mat_color.g);
        SET_REG_FIELD(0, reg, 8, 24, mat_color.r);
        colIdx = 1;
        break;
    default:
        ASSERTMSGLINE(832, 0, "GXSetChanMatColor: Invalid Channel Id");
        return;
    }

    GX_WRITE_XF_REG(colIdx + 12, reg);
    __GXData->bpSentNot = 1;
    __GXData->matColor[colIdx] = reg;
}

void GXSetNumChans(u8 nChans) {
    u32* reg;
    u32 n;

    CHECK_GXBEGIN(857, "GXSetNumChans");
    ASSERTMSGLINE(858, nChans <= 2, "GXSetNumChans: nChans > 2");

    n = nChans;
    reg = &__GXData->genMode;
    *reg = (*reg & ~0x70U) | (n << 4);
    GX_WRITE_U8(0x10);
    GX_WRITE_U32(0x1009);
    GX_WRITE_U32(n);
    __GXData->dirtyState |= 4;
}

asm void GXSetChanCtrl(GXChannelID chan, GXBool enable, GXColorSrc amb_src, GXColorSrc mat_src, u32 light_mask, GXDiffuseFn diff_fn, GXAttnFn attn_fn) {
    nofralloc
    stwu r1, -0x38(r1)
    cmpwi r3, 0x4
    stw r31, 0x34(r1)
    stw r30, 0x30(r1)
    stw r29, 0x2c(r1)
    stw r28, 0x28(r1)
    bne _gscc_0
    li r11, 0x0
    b _gscc_2
_gscc_0:
    cmpwi r3, 0x5
    bne _gscc_1
    li r11, 0x1
    b _gscc_2
_gscc_1:
    mr r11, r3
_gscc_2:
    clrlslwi r4, r4, 24, 1
    or r10, r4, r6
    clrlwi r0, r7, 31
    neg r6, r0
    subic r4, r6, 0x1
    rlwinm r0, r7, 0, 30, 30
    neg r12, r0
    subfe r6, r4, r6
    subic r4, r12, 0x1
    subfe r4, r4, r12
    rlwinm r0, r7, 0, 29, 29
    neg r28, r0
    subic r0, r28, 0x1
    rlwinm r12, r7, 0, 28, 28
    subfe r0, r0, r28
    neg r29, r12
    subic r28, r29, 0x1
    rlwinm r12, r7, 0, 27, 27
    neg r30, r12
    subfe r28, r28, r29
    subic r29, r30, 0x1
    rlwinm r12, r7, 0, 26, 26
    neg r31, r12
    subfe r29, r29, r30
    subic r30, r31, 0x1
    rlwinm r12, r7, 0, 25, 25
    subfe r30, r30, r31
    neg r31, r12
    subic r12, r31, 0x1
    rlwinm r10, r10, 0, 26, 24
    slwi r5, r5, 6
    or r5, r10, r5
    rlwinm r10, r5, 0, 30, 28
    slwi r5, r6, 2
    or r5, r10, r5
    rlwinm r5, r5, 0, 29, 27
    slwi r4, r4, 3
    or r4, r5, r4
    rlwinm r4, r4, 0, 28, 26
    slwi r0, r0, 4
    or r0, r4, r0
    rlwinm r4, r0, 0, 27, 25
    slwi r0, r28, 5
    or r0, r4, r0
    rlwinm r4, r0, 0, 21, 19
    slwi r0, r29, 11
    or r0, r4, r0
    rlwinm r4, r0, 0, 20, 18
    slwi r0, r30, 12
    or r0, r4, r0
    rlwinm r7, r7, 0, 24, 24
    subfe r31, r12, r31
    neg r12, r7
    subic r7, r12, 0x1
    rlwinm r4, r0, 0, 19, 17
    slwi r0, r31, 13
    or r0, r4, r0
    subfe r7, r7, r12
    rlwinm r4, r0, 0, 18, 16
    slwi r0, r7, 14
    cmpwi r9, 0x0
    or r6, r4, r0
    bne _gscc_3
    li r8, 0x0
_gscc_3:
    subfic r5, r9, 0x2
    lwz r4, gx(r13)
    subic r0, r5, 0x1
    subfe r10, r0, r5
    neg r5, r9
    subic r0, r5, 0x1
    subfe r7, r0, r5
    rlwinm r5, r6, 0, 25, 22
    slwi r0, r8, 7
    or r8, r5, r0
    li r6, 0x10
    lis r5, 0xcc01
    stb r6, -0x8000(r5)
    addi r0, r11, 0x100e
    rlwinm r9, r8, 0, 23, 21
    slwi r8, r10, 9
    stw r0, -0x8000(r5)
    or r0, r9, r8
    rlwinm r8, r0, 0, 22, 20
    slwi r0, r7, 10
    or r7, r8, r0
    stw r7, -0x8000(r5)
    li r0, 0x1
    cmpwi r3, 0x4
    sth r0, 0x2(r4)
    bne _gscc_4
    stb r6, -0x8000(r5)
    li r0, 0x1010
    stw r0, -0x8000(r5)
    stw r7, -0x8000(r5)
    b _gscc_5
_gscc_4:
    cmpwi r3, 0x5
    bne _gscc_5
    stb r6, -0x8000(r5)
    li r0, 0x1011
    stw r0, -0x8000(r5)
    stw r7, -0x8000(r5)
_gscc_5:
    lwz r31, 0x34(r1)
    lwz r30, 0x30(r1)
    lwz r29, 0x2c(r1)
    lwz r28, 0x28(r1)
    addi r1, r1, 0x38
    blr
}
