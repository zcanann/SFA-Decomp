#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

#pragma fp_contract off

extern GXData* gx;
#define __GXData gx

extern const f32 lbl_803E8318;
extern const f32 lbl_803E831C;
extern const f32 lbl_803E8320;
extern const f32 lbl_803E8324;
extern const f32 lbl_803E8328;
extern const f32 lbl_803E832C;
extern const f32 lbl_803E8330;
extern const f32 lbl_803E8334;
extern const f32 lbl_803E8338;
extern const f32 lbl_803E833C;
extern const f32 lbl_803E8340;
extern const f32 lbl_803E8344;
extern const f32 lbl_803E8348;
extern const double lbl_803E8350;
extern const double lbl_803E8358;
extern const f32 lbl_803E8360[2];

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

void GXSetChanCtrl(GXChannelID chan, GXBool enable, GXColorSrc amb_src, GXColorSrc mat_src, u32 light_mask,
                   GXDiffuseFn diff_fn, GXAttnFn attn_fn) {
    u32 reg;
    u32 idx;

    CHECK_GXBEGIN(760, "GXSetChanCtrl");

    if (chan == GX_COLOR0A0) {
        idx = GX_COLOR0;
    } else if (chan == GX_COLOR1A1) {
        idx = GX_COLOR1;
    } else {
        idx = chan;
    }

    reg = 0;
    SET_REG_FIELD(770, reg, 1, 1, enable);
    SET_REG_FIELD(771, reg, 1, 0, mat_src);
    SET_REG_FIELD(772, reg, 1, 6, amb_src);
    SET_REG_FIELD(773, reg, 1, 2, (light_mask & GX_LIGHT0) != 0);
    SET_REG_FIELD(774, reg, 1, 3, (light_mask & GX_LIGHT1) != 0);
    SET_REG_FIELD(775, reg, 1, 4, (light_mask & GX_LIGHT2) != 0);
    SET_REG_FIELD(776, reg, 1, 5, (light_mask & GX_LIGHT3) != 0);
    SET_REG_FIELD(777, reg, 1, 11, (light_mask & GX_LIGHT4) != 0);
    SET_REG_FIELD(778, reg, 1, 12, (light_mask & GX_LIGHT5) != 0);
    SET_REG_FIELD(779, reg, 1, 13, (light_mask & GX_LIGHT6) != 0);
    SET_REG_FIELD(780, reg, 1, 14, (light_mask & GX_LIGHT7) != 0);
    SET_REG_FIELD(782, reg, 2, 7, (attn_fn == GX_AF_NONE) ? GX_DF_NONE : diff_fn);
    SET_REG_FIELD(783, reg, 1, 9, (attn_fn != GX_AF_SPEC));
    SET_REG_FIELD(784, reg, 1, 10, (attn_fn != GX_AF_NONE));

    GX_WRITE_XF_REG(idx + 14, reg);
    __GXData->bpSentNot = 1;

    if (chan == GX_COLOR0A0) {
        GX_WRITE_XF_REG(16, reg);
    } else if (chan == GX_COLOR1A1) {
        GX_WRITE_XF_REG(17, reg);
    }
}
