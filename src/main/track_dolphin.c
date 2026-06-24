#include "main/map_block.h"
#include "main/frustum.h"
#include "main/asset_load.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "dolphin/os/OSFastCast.h"
#include "main/camera.h"
#include "main/gameplay_runtime.h"
#include "main/sky_state.h"
#include "main/track_dolphin.h"
#include "dolphin/os/OSCache.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
#define GX_COLOR0A0 4
#define GX_COLOR1A1 5
#define GX_COLOR_NULL 0xff
#define GX_DISABLE 0
#define GX_ENABLE 1
#define GX_SRC_REG 0
#define GX_DF_NONE 0
#define GX_AF_NONE 2
#define GX_TEVSTAGE0 0
#define GX_TEXCOORD0 0
#define GX_TEXMAP0 0
#define GX_CC_ZERO 0xf
#define GX_CA_TEXA 4
#define GX_CA_KONST 6
#define GX_CA_ZERO 7
#define GX_TEV_ADD 0
#define GX_TB_ZERO 0
#define GX_CS_SCALE_1 0
#define GX_TEVPREV 0
#define GX_BM_BLEND 1
#define GX_BL_SRCALPHA 4
#define GX_BL_INVSRCALPHA 5
#define GX_LO_NOOP 5

typedef struct TrackP6Entry
{
    f32 relX0;
    f32 relY0;
    f32 relZ0;
    f32 relX1;
    f32 relY1;
    f32 relZ1;
    f32 relX2;
    f32 relY2;
    f32 relZ2;
} TrackP6Entry;

#pragma peephole off
#pragma scheduling off
extern u32 FUN_800068ec();
extern u32 FUN_800068f0();
extern u32 FUN_800068f4();
extern u64 FUN_800068f8();
extern u32 FUN_80006904();
extern u32 FUN_80017784();
extern u32 FUN_80017790();
extern u32 FUN_8001779c();
extern int FUN_80017830();
extern void* ObjGroup_GetObjects();
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern u32 FUN_802475e4();
extern u32 FUN_80247618();
extern u32 FUN_802585d8();
extern u32 FUN_8025d80c();
extern u32 FUN_8025d848();
extern u32 FUN_8025d8c4();
extern u32 FUN_80292b48();
extern double FUN_80293900();
extern u32 FUN_802947f8();
extern u32 FUN_802949e8();
extern u32 FUN_80294da4();
extern int DAT_80382c98;
extern u32 DAT_8038859c;
extern u32 DAT_803885a0;
extern u32 DAT_803885a4;
extern u32 DAT_803885a8;
extern int DAT_8038e8c4;
extern u32 DAT_8038e8c8;
extern int DAT_8038eaa4;
extern u32 DAT_80397450;
extern u32 DAT_803dc2b8;
extern u32 DAT_803dda86;
extern u32 DAT_803ddbb0;
extern u32 DAT_803ddbb4;
extern float* DAT_803ddbb8;
extern u32 DAT_803ddbbc;
extern int* DAT_803ddbc8;
extern u32 DAT_803ddbcd;
extern u32 DAT_803ddbce;
extern u32 DAT_803ddbcf;
extern u32 DAT_803ddbdc;
extern u32 DAT_803ddbde;
extern u32 DAT_803ddbec;
extern u32 DAT_803ddc00;
extern u32 DAT_803ddc38;
extern f64 DOUBLE_803df840;
extern f64 DOUBLE_803df958;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDBD0;
extern const f32 lbl_803DDBD4;
extern f32 lbl_803DDBD8;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF8A0;
extern const f32 lbl_803DEC50;
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 __AR_Callback;
extern f32 __AR_Size;
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern void vecRotateZXY(void* xf, f32* out);
extern f32 lbl_8038D7DC[];
extern s16 gShadowVisibleCount;
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * out);
extern void PSVECScale(f32* src, f32* dst, f32 s);
extern const f32 lbl_803DEC6C;
extern const f32 lbl_803DEC70;
extern const f32 lbl_803DEC74;
extern void PSVECNormalize(f32 * src, f32 * dst);
extern f32 sqrtf(f32 x);
extern f32 gPrevSunDir[];
extern s16 gSunMagnitude;
extern f32 gSunDotCos;
extern int gSunDirChanged;
extern f32 __AR_init_flag;
extern f32 __AR_BlockLength;
extern const f32 lbl_803DEC58;
extern const f32 lbl_803DEC68;
extern f32 gShadowOffsetX;
extern f32 gShadowOffsetZ;
extern f32 gShadowOffsetY;
extern void* textureLoad(int texId, u8 flag);
extern int textureAlloc512(void);
extern u32 textureFn_8006c5c4(void);
extern f32 lbl_803DB654;
extern f32 lbl_803DEC90[2];
extern f32 lbl_803DEC94;
extern int lbl_803DCFB8;
extern u8 lbl_803DCF80;
extern f32 lbl_803DF930;
extern f32 lbl_803DF934;
extern f32 lbl_803DF938;
extern f32 lbl_803DF93C;
extern f32 lbl_803DF940;
extern f32 lbl_803DF944;
extern f32 lbl_803DF948;
extern f32 lbl_803DF96C;

void mapBlockRender_setVtxDcrs(flag, obj, sh, bs)
u8 flag;
int* obj;
int sh;

int* bs;
{
    extern void GXClearVtxDesc(void);
    extern void GXSetVtxDesc(int attr, int type);
    u32 val;
    int pos;
    int off;
    u8* p;
    int bit;
    u32 val2;
    int pos2;
    int off2;
    u8* q;
    int bit2;
    u32 val3;
    int pos3;
    int off3;
    u8* r;
    int bit3;
    int i;

    if (flag != 0)
    {
        GXClearVtxDesc();
    }
    pos = bs[4];
    off = pos >> 3;
    val = *(u8*)(bs[0] + off);
    p = (u8*)bs[0] + off;
    val |= p[1] << 8;
    val |= p[2] << 16;
    bs[4] = pos + 1;
    bit = (val >> (pos & 7)) & 1;
    if (flag != 0)
    {
        GXSetVtxDesc(9, bit ? 3 : 2);
    }
    pos2 = bs[4];
    off2 = pos2 >> 3;
    val2 = *(u8*)(bs[0] + off2);
    q = (u8*)bs[0] + off2;
    val2 |= q[1] << 8;
    val2 |= q[2] << 16;
    bs[4] = pos2 + 1;
    bit2 = (val2 >> (pos2 & 7)) & 1;
    if (flag != 0)
    {
        GXSetVtxDesc(11, bit2 ? 3 : 2);
    }
    pos3 = bs[4];
    off3 = pos3 >> 3;
    val3 = *(u8*)(bs[0] + off3);
    r = (u8*)bs[0] + off3;
    val3 |= r[1] << 8;
    val3 |= r[2] << 16;
    bs[4] = pos3 + 1;
    bit3 = (val3 >> (pos3 & 7)) & 1;
    if (flag != 0)
    {
        if ((u32)sh != 0 && (*(u32*)(sh + 0x3c) & 0x80000000) == 0)
        {
            for (i = 0; i < *(u8*)(sh + 0x41); i++)
            {
                GXSetVtxDesc(i + 13, bit3 ? 3 : 2);
            }
        }
        else
        {
            GXSetVtxDesc(13, bit3 ? 3 : 2);
        }
    }
}

void FUN_8005fab0(int block, float* posMtx)
{
    float nrmMtx[3];
    float nrmMtxW0;
    float nrmMtxW1;
    float nrmMtxW2;
    float texMtx[12];

    FUN_8025d80c(posMtx, 0);
    FUN_802475e4(posMtx, nrmMtx);
    nrmMtxW0 = lbl_803DF84C;
    nrmMtxW1 = lbl_803DF84C;
    nrmMtxW2 = lbl_803DF84C;
    FUN_8025d848(nrmMtx, 0);
    FUN_80247618((float*)&DAT_80397450, posMtx, texMtx);
    FUN_8025d8c4(texMtx, 0x24, 0);
    FUN_802585d8(9, *(u32*)(block + 0x58), 6);
    FUN_802585d8(0xb, *(u32*)(block + 0x5c), 2);
    FUN_802585d8(0xd, *(u32*)(block + 0x60), 4);
    FUN_802585d8(0xe, *(u32*)(block + 0x60), 4);
    return;
}

extern void GXLoadPosMtxImm(void* mtx, int slot);
extern void PSMTXCopy(void* src, void* dst);
extern void GXLoadNrmMtxImm(void* mtx, int slot);
extern void PSMTXConcat(void* a, void* b, void* out);
extern void GXLoadTexMtxImm(void* mtx, int slot, int type);
extern void GXSetArray(int attr, void* base, int stride);
extern f32 lbl_803DEBCC;
extern u8 lbl_803967F0[];

#pragma dont_inline on
void setupToRenderMapBlock(int* block, void* posMtx)
{
    f32 out[12];
    f32 tmp[12];
    f32 fc;

    GXLoadPosMtxImm(posMtx, 0);
    PSMTXCopy(posMtx, tmp);
    fc = lbl_803DEBCC;
    tmp[3] = fc;
    tmp[7] = fc;
    tmp[11] = fc;
    GXLoadNrmMtxImm(tmp, 0);
    PSMTXConcat(lbl_803967F0, posMtx, out);
    GXLoadTexMtxImm(out, 0x24, 0);
    GXSetArray(9, *(void**)((char*)block + 0x58), 6);
    GXSetArray(11, *(void**)((char*)block + 0x5C), 2);
    GXSetArray(13, *(void**)((char*)block + 0x60), 4);
    GXSetArray(14, *(void**)((char*)block + 0x60), 4);
}
#pragma dont_inline reset

extern void modelRenderInstrsState_init(int* state, int ptr, int a, int b);
extern int mapBlockRender_setShader(int a, int* obj, int* state);
extern void mapBlockRender_callList(int a, int b, int* obj, int shader, int* state, f32* m);

#pragma push
#pragma scheduling off
void renderMapBlock(int* o, u8 type)
{
    int state[5];
    f32 m[16];
    int ptr;
    int count;
    int shader;
    int flag;
    void* viewMtx;

    shader = 0;
    flag = 0;
    if (type == 1)
    {
        ptr = *(int*)&((GameObject*)o)->anim.banks;
        count = *(u16*)((char*)o + 0x86);
    }
    else if (type == 2)
    {
        ptr = *(int*)&((GameObject*)o)->anim.previousLocalPosX;
        count = *(u16*)((char*)o + 0x88);
    }
    else
    {
        ptr = *(int*)&((GameObject*)o)->anim.hitVolumeBounds;
        count = *(u16*)((char*)o + 0x84);
        flag = 1;
    }
    if ((u16)count == 0) return;
    viewMtx = Camera_GetViewMatrix();
    PSMTXConcat(viewMtx, (char*)o + 0xc, m);
    if ((u32)(u8)flag != 0
    )
    setupToRenderMapBlock(o, m);
    modelRenderInstrsState_init(state, ptr, (u16)count << 3, (u16)count << 3);
    ptr = 0;
    while (!ptr)
    {
        u32 word;
        int op;
        int pos = state[4];
        u8* bp = (u8*)((pos >> 3) + state[0]);
        word = bp[0];
        word |= bp[1] << 8;
        word |= bp[2] << 16;
        state[4] = pos + 4;
        op = (word >> (pos & 7)) & 0xf;
        switch (op)
        {
        case 3:
            mapBlockRender_setVtxDcrs(flag, o, shader, state);
            break;
        case 1:
            shader = mapBlockRender_setShader(flag, o, state);
            break;
        case 2:
            mapBlockRender_callList(flag, 0, o, shader, state, m);
            break;
        case 4:
            {
                u32 word2;
                int cnt;
                int j;
                u8* bp2;
                int pos2 = pos + 4;
                bp2 = (u8*)(state[0] + (pos2 >> 3));
                word2 = bp2[0];
                word2 |= bp2[1] << 8;
                word2 |= bp2[2] << 16;
                state[4] = pos2 + 4;
                cnt = (word2 >> (pos2 & 7)) & 0xf;
                for (j = 0; j < cnt; j++)
                    ((int volatile*)state)[4] = state[4] + 8;
                break;
            }
        case 5:
            ptr = 1;
            break;
        }
    }
}
#pragma pop

void FUN_8005fe14(int obj)
{
    bool insideFrustum;
    u32 planeIdx;
    u8 plane;

    if (99 < DAT_803dda86)
    {
        return;
    }
    plane = 0;
    do
    {
        if (4 < plane)
        {
            insideFrustum = true;
        LAB_800606c0:
            if ((!insideFrustum) && (*(char*)(obj + 0x2f9) == '\0'))
            {
                return;
            }
            if (!insideFrustum)
            {
                *(u8*)(obj + 0x2fa) = 0xf0;
            }
            planeIdx = DAT_803dda86;
            DAT_803dda86 = DAT_803dda86 + 1;
            (&DAT_80382c98)[planeIdx] = obj;
            return;
        }
        planeIdx = plane;
        if (lbl_803DF84C +
            (float)(&DAT_803885a8)[planeIdx * 5] +
            (float)(&DAT_803885a4)[planeIdx * 5] * (((GameObject*)obj)->anim.worldPosX - lbl_803DDA5C) +
            ((GameObject*)obj)->anim.localPosZ * (float)(&DAT_803885a0)[planeIdx * 5] +
            (float)(&DAT_8038859c)[planeIdx * 5] * (((GameObject*)obj)->anim.localPosY - lbl_803DDA58) <
            lbl_803DF84C)
        {
            insideFrustum = false;
            goto LAB_800606c0;
        }
        plane = plane + 1;
    }
    while (true);
}

void FUN_8005ff90(short* in, float* out)
{
    double bias;
    float scale;

    scale = lbl_803DF8A0;
    bias = DOUBLE_803df840;
    *out = (float)((double)(int)*in) *
        lbl_803DF8A0;
    out[1] = (float)((double)(int)in[1]) * scale;
    out[2] = (float)((double)(int)in[2]) * scale;
    return;
}

u32 FUN_80060058(int obj)
{
    return *(u32*)&((GameObject*)obj)->anim.localPosY >> 0x18;
}

int FUN_800600b4(int obj, int idx)
{
    return *(int*)&((GameObject*)obj)->anim.placementData + idx * 8;
}

int FUN_800600c4(int obj, int idx)
{
    return *(int*)&((GameObject*)obj)->anim.modelInstance + idx * 0x14;
}

int FUN_800600d4(int obj, int idx)
{
    return *(int*)&((GameObject*)obj)->anim.dll + idx * 0x1c;
}

int FUN_800600e4(int obj, int idx)
{
    return *(int*)&((GameObject*)obj)->anim.modelState + idx * 0x44;
}

u32 FUN_8006069c(void)
{
    return 0;
}

void FUN_8006070c(u64 param_1, double param_2, u32 param_3, u32 param_4,
                  int param_5, float* param_6, u32 param_7, u32 param_8, int param_9)
{
}

void FUN_80060a64(u16* param_1, int param_2)
{
}

void FUN_80061194(void)
{
}

void FUN_800614d0(u8 value)
{
    DAT_803dc2b8 = value;
    return;
}

void FUN_80061a80(short* obj, short* newParent, int mode)
{
    int outObj;
    short* prevParent;
    int angle;
    float localZ;
    float localX;
    float localY[4];

    prevParent = *(short**)(obj + 0x18);
    if (prevParent != newParent)
    {
        if (prevParent != 0x0)
        {
            FUN_80006904();
        }
        if (newParent != 0x0)
        {
            FUN_80006904();
        }
        if (obj[0x22] == 1)
        {
            FUN_80294da4();
        }
        else
        {
            *(short**)(obj + 0x18) = newParent;
            outObj = *(int*)(obj + 0x2a);
            if (prevParent == 0x0)
            {
                localX = *(float*)(obj + 0x12);
                localZ = *(float*)(obj + 0x16);
                angle = (int)*obj;
            }
            else
            {
                FUN_800068f8((double)*(float*)(obj + 6), (double)*(float*)(obj + 8),
                             (double)*(float*)(obj + 10), (float*)(obj + 0xc),
                             (float*)(obj + 0xe), (float*)(obj + 0x10), prevParent);
                FUN_800068f8((double)*(float*)(obj + 0x40), (double)*(float*)(obj + 0x42),
                             (double)*(float*)(obj + 0x44), (float*)(obj + 0x46),
                             (float*)(obj + 0x48), (float*)(obj + 0x4a), prevParent);
                FUN_800068ec((double)*(float*)(obj + 0x12), (double)lbl_803DF934,
                             (double)*(float*)(obj + 0x16), &localX, localY, &localZ, prevParent);
                angle = (int)*prevParent + (int)*obj;
            }
            if (mode != 0)
            {
                if (*(int*)(obj + 0x18) == 0)
                {
                    *(u32*)(obj + 6) = *(u32*)(obj + 0xc);
                    *(u32*)(obj + 8) = *(u32*)(obj + 0xe);
                    *(u32*)(obj + 10) = *(u32*)(obj + 0x10);
                    *(u32*)(obj + 0x40) = *(u32*)(obj + 0x46);
                    *(u32*)(obj + 0x42) = *(u32*)(obj + 0x48);
                    *(u32*)(obj + 0x44) = *(u32*)(obj + 0x4a);
                    *(float*)(obj + 0x12) = localX;
                    *(float*)(obj + 0x16) = localZ;
                    *obj = angle;
                }
                else
                {
                    FUN_800068f4((double)*(float*)(obj + 0xc), (double)*(float*)(obj + 0xe),
                                 (double)*(float*)(obj + 0x10), (float*)(obj + 6),
                                 (float*)(obj + 8), (float*)(obj + 10), *(int*)(obj + 0x18));
                    FUN_800068f4((double)*(float*)(obj + 0x46), (double)*(float*)(obj + 0x48),
                                 (double)*(float*)(obj + 0x4a), (float*)(obj + 0x40),
                                 (float*)(obj + 0x42), (float*)(obj + 0x44), *(int*)(obj + 0x18));
                    FUN_800068f0((double)localX, (double)lbl_803DF934, (double)localZ,
                                 (float*)(obj + 0x12), localY, (float*)(obj + 0x16),
                                 *(int*)(obj + 0x18));
                    angle = angle - **(short**)(obj + 0x18);
                    if (0x8000 < angle)
                    {
                        angle = angle + -0xffff;
                    }
                    if (angle < -0x8000)
                    {
                        angle = angle + 0xffff;
                    }
                    *obj = angle;
                }
            }
            if (outObj != 0)
            {
                *(u32*)(outObj + 0x10) = *(u32*)(obj + 6);
                *(u32*)(outObj + 0x14) = *(u32*)(obj + 8);
                *(u32*)(outObj + 0x18) = *(u32*)(obj + 10);
                *(u32*)(outObj + 0x1c) = *(u32*)(obj + 0xc);
                *(u32*)(outObj + 0x20) = *(u32*)(obj + 0xe);
                *(u32*)(outObj + 0x24) = *(u32*)(obj + 0x10);
            }
        }
    }
    return;
}

u32
FUN_80061cbc(double cx, double cy, double r, float* px, float* py, char resolve
)
{
    float dot;
    double dVar2;
    double dVar3;
    double dVar4;
    double dVar5;
    double dVar6;
    double segDy;
    double segDx;

    dVar2 = (double)lbl_803DF934;
    if (dVar2 != r)
    {
        dVar5 = (double)*px;
        dVar4 = (double)(float)(dVar5 - cx);
        dVar3 = (double)(float)((double)*py - cy);
        dVar6 = -(double)(float)(r * r -
            (double)((float)(dVar4 * dVar4) + (float)(dVar3 * dVar3)));
        if (dVar2 <= dVar6)
        {
            segDx = (double)(float)((double)px[1] - dVar5);
            segDy = (double)(float)((double)py[1] - (double)*py);
            dVar5 = (double)(float)(segDx * segDx + (double)(float)(segDy * segDy));
            if (dVar2 < dVar5)
            {
                dVar4 = (double)(lbl_803DF938 * (float)(segDx * dVar4 + (double)(float)(segDy * dVar3)));
                dVar3 = (double)(float)(dVar4 * dVar4 -
                    (double)(float)((double)(float)((double)lbl_803DF93C * dVar5) *
                        dVar6));
                if (dVar2 <= dVar3)
                {
                    dVar3 = FUN_80293900(dVar3);
                    dVar2 = (double)((float)(-dVar4 + dVar3) / (float)((double)lbl_803DF938 * dVar5));
                    dVar3 = (double)((float)(-dVar4 - dVar3) / (float)((double)lbl_803DF938 * dVar5));
                    if (dVar2 < (double)lbl_803DF934)
                    {
                        dVar2 = (double)lbl_803DF940;
                    }
                    if (dVar3 < (double)lbl_803DF934)
                    {
                        dVar3 = (double)lbl_803DF940;
                    }
                    if (dVar3 < dVar2)
                    {
                        dVar2 = dVar3;
                    }
                    if (((double)lbl_803DF934 <= dVar2) && (dVar2 <= (double)lbl_803DF944))
                    {
                        lbl_803DDBD8 = (float)dVar2;
                        if (resolve != '\0')
                        {
                            dVar3 = (double)(float)(dVar2 * segDx + (double)*px);
                            dVar2 = (double)(float)(dVar2 * segDy + (double)*py);
                            dVar4 = (double)(float)((double)(float)(dVar3 - cx) / r);
                            dVar5 = (double)(float)((double)(float)(dVar2 - cy) / r);
                            dot = -(float)(dVar3 * dVar4 + (double)(float)(dVar2 * dVar5));
                            dVar2 = (double)(dot + (float)(dVar4 * (double)px[1] +
                                (double)(float)(dVar5 * (double)py[1])));
                            px[1] = -(float)(dVar2 * dVar4 - (double)px[1]);
                            py[1] = -(float)(dVar2 * dVar5 - (double)py[1]);
                            dVar2 = (double)lbl_803DF948;
                            while ((double)(dot + (float)((double)px[1] * dVar4 +
                                (double)(float)((double)py[1] * dVar5))) < dVar2)
                            {
                                px[1] = px[1] + (float)(dVar2 * dVar4);
                                py[1] = py[1] + (float)(dVar2 * dVar5);
                            }
                        }
                        return 1;
                    }
                }
            }
        }
        else if (resolve != '\0')
        {
            px[1] = (float)(dVar5 + (double)lbl_803DDBD4);
            py[1] = *py + lbl_803DDBD0;
        }
    }
    return 0;
}

int FUN_80062010(double x, double y, double z, u16 tag, int linkArr)
{
    int vtxCount;
    float* vtxPtr;
    int idx;
    int remaining;

    idx = 0;
    vtxCount = DAT_803ddbdc;
    vtxPtr = DAT_803ddbb8;
    remaining = vtxCount;
    if (0 < vtxCount)
    {
        do
        {
            if (((x == (double)*vtxPtr) && (y == (double)vtxPtr[1])) &&
                (z == (double)vtxPtr[2]))
            {
                *(u16*)(linkArr + idx * 4 + 2) = tag;
                return idx;
            }
            vtxPtr = vtxPtr + 3;
            idx = idx + 1;
            remaining = remaining + -1;
        }
        while (remaining != 0);
    }
    DAT_803ddbb8[vtxCount * 3] = (float)x;
    DAT_803ddbb8[DAT_803ddbdc * 3 + 1] = (float)y;
    DAT_803ddbb8[DAT_803ddbdc * 3 + 2] = (float)z;
    *(u16*)(linkArr + DAT_803ddbdc * 4) = tag;
    *(u16*)(linkArr + DAT_803ddbdc * 4 + 2) = 0xffff;
    DAT_803ddbdc = DAT_803ddbdc + 1;
    return DAT_803ddbdc + -1;
}

void FUN_800620e8(u32 param_1, u32 param_2, float* param_3, int* param_4, int* param_5,
                  u32 param_6, u32 param_7, u32 param_8, u8 param_9)
{
}

void FUN_800631d4(int tag, int obj, int clear)
{
    u32 hitCount;
    int hitEntry;

    if (obj == 0)
    {
        hitCount = DAT_803ddbde;
        hitEntry = DAT_803ddbb4;
    }
    else
    {
        hitCount = (u32) * (u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x5c);
        hitEntry = *(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x34);
    }
    if (clear != 0)
    {
        if ((int)hitCount < 1)
        {
            return;
        }
        do
        {
            if (*(short*)(hitEntry + 0xc) == tag)
            {
                *(u8*)(hitEntry + 3) = *(u8*)(hitEntry + 3) & 0xbf;
            }
            hitEntry = hitEntry + 0x10;
            hitCount = hitCount - 1;
        }
        while (hitCount != 0);
        return;
    }
    if ((int)hitCount < 1)
    {
        return;
    }
    do
    {
        if (*(short*)(hitEntry + 0xc) == tag)
        {
            *(u8*)(hitEntry + 3) = *(u8*)(hitEntry + 3) | 0x40;
        }
        hitEntry = hitEntry + 0x10;
        hitCount = hitCount - 1;
    }
    while (hitCount != 0);
    return;
}

u32 FUN_80063298(void)
{
    if (((DAT_803ddbce == '\0') && (DAT_803ddbcf == '\0')) && (DAT_803ddbcd == '\0'))
    {
        return 0;
    }
    return 1;
}

u32
FUN_800632d8(u64 param_1, double param_2, double param_3, u32 param_4, float* param_5,
             u32 param_6)
{
    return 0;
}

u32
FUN_800632e0(u64 param_1, double param_2, double param_3, u32 param_4, float* param_5,
             u32* param_6, u32 param_7)
{
    return 0;
}

u32
FUN_800632e8(u64 param_1, double param_2, double param_3, u32 param_4, float* param_5,
             u32 param_6)
{
    return 0;
}

void FUN_800632f4(u64 param_1, double param_2, double param_3, u32 param_4,
                  u32 param_5, int param_6, u32 param_7)
{
}

u32
FUN_800632f8(double param_1, double param_2, float* param_3, float* param_4, float* param_5,
             float* param_6, u8 param_7)
{
    float scratch1;
    float scratch2;
    float t;
    double len;
    double dist;
    float normX;
    float normY;
    float normZ;
    float dx;
    float dy;
    float dz;

    if (param_7 == 3)
    {
        *param_4 = *param_5;
        param_4[1] = param_5[1];
        param_4[2] = param_5[2];
        dx = *param_4 - *param_3;
        dy = param_4[1] - param_3[1];
        dz = param_4[2] - param_3[2];
        FUN_80017784(&dx);
        scratch1 = (float)((double)(param_6[3] +
                param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1])
            - param_2);
        scratch2 = (float)((double)(param_6[3] +
                param_3[2] * param_6[2] + *param_3 * *param_6 + param_3[1] * param_6[1])
            - param_2);
        t = lbl_803DF934;
        if (scratch2 != scratch1)
        {
            t = scratch2 / (scratch2 - scratch1);
        }
        scratch1 = param_3[1];
        scratch2 = param_3[2];
        *param_4 = (*param_4 - *param_3) * t;
        param_4[1] = (param_4[1] - scratch1) * t;
        param_4[2] = (param_4[2] - scratch2) * t;
        *param_4 = *param_4 + *param_3;
        param_4[1] = param_4[1] + param_3[1];
        param_4[2] = param_4[2] + param_3[2];
        return 1;
    }
    if ((lbl_803DF930 <= param_6[1]) || (param_6[1] <= lbl_803DF96C))
    {
        if ((param_7 != 8) && ((7 < param_7 || (param_7 != 5))))
        {
            scratch1 = param_6[2];
            scratch2 = *param_6;
            dist = (double)(float)(param_2 -
                (double)(param_6[3] +
                    param_4[2] * scratch1 + *param_4 * scratch2 + param_4[1] * param_6[1]
                ));
            if (dist <= (double)lbl_803DF934)
            {
                return 1;
            }
            FUN_80293900((double)(scratch2 * scratch2 + scratch1 * scratch1));
            FUN_80292b48();
            len = (double)FUN_802947f8();
            param_4[1] = param_4[1] + (float)(dist / len);
            return 1;
        }
        *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
        param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
        param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
        scratch1 = (float)(param_2 -
            (double)(param_6[3] +
                param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]));
        *param_4 = scratch1 * *param_6 + *param_4;
        param_4[1] = scratch1 * param_6[1] + param_4[1];
        param_4[2] = scratch1 * param_6[2] + param_4[2];
        return 1;
    }
    if (param_7 == 8)
    {
    LAB_800663f8:
        scratch1 = param_6[2];
        scratch2 = *param_6;
        dist = (double)(float)(param_2 -
            (double)(param_6[3] +
                param_4[2] * scratch1 + *param_4 * scratch2 + param_4[1] * param_6[1]));
        if ((double)lbl_803DF934 < dist)
        {
            FUN_80293900((double)(scratch2 * scratch2 + scratch1 * scratch1));
            FUN_80292b48();
            len = (double)FUN_802949e8();
            if ((double)lbl_803DF934 != len)
            {
                dist = (double)(float)(dist / len);
            }
            normX = *param_6;
            normY = lbl_803DF934;
            normZ = param_6[2];
            FUN_80017784(&normX);
            *param_4 = (float)(dist * (double)normX + (double)*param_4);
            param_4[2] = (float)(dist * (double)normZ + (double)param_4[2]);
        }
    }
    else
    {
        if (param_7 < 8)
        {
            if (param_7 == 1) goto LAB_800663f8;
        }
        else if (param_7 == 10) goto LAB_800663f8;
        *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
        param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
        param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
        scratch1 = (float)(param_2 -
            (double)(param_6[3] +
                param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]));
        *param_4 = scratch1 * *param_6 + *param_4;
        param_4[1] = scratch1 * param_6[1] + param_4[1];
        param_4[2] = scratch1 * param_6[2] + param_4[2];
    }
    return 1;
}

void FUN_80063a68(void)
{
}

void FUN_80063a74(u32 param_1, u32 param_2, u32 param_3, char param_4)
{
}

void trackDolphin_buildSweptBounds(u32* boundsOut, float* startPoints, float* endPoints,
                                   float* radii, int pointCount)
{
    double bias;
    u64 convTmp;

    *boundsOut = 1000000;
    boundsOut[3] = 0xfff0bdc0;
    boundsOut[1] = 1000000;
    boundsOut[4] = 0xfff0bdc0;
    boundsOut[2] = 1000000;
    boundsOut[5] = 0xfff0bdc0;
    bias = DOUBLE_803df958;
    if (pointCount != 0)
    {
        do
        {
            convTmp = (double)(int)*boundsOut;
            if (*startPoints - *radii < (float)(convTmp))
            {
                *boundsOut = (int)(*startPoints - *radii);
            }
            convTmp = (double)(int)boundsOut[3];
            if ((float)(convTmp) < *startPoints + *radii)
            {
                boundsOut[3] = (int)(*startPoints + *radii);
            }
            convTmp = (double)(int)boundsOut[1];
            if (startPoints[1] - *radii < (float)(convTmp))
            {
                boundsOut[1] = (int)(startPoints[1] - *radii);
            }
            convTmp = (double)(int)boundsOut[4];
            if ((float)(convTmp) < startPoints[1] + *radii)
            {
                boundsOut[4] = (int)(startPoints[1] + *radii);
            }
            convTmp = (double)(int)boundsOut[2];
            if (startPoints[2] - *radii < (float)(convTmp))
            {
                boundsOut[2] = (int)(startPoints[2] - *radii);
            }
            convTmp = (double)(int)boundsOut[5];
            if ((float)(convTmp) < startPoints[2] + *radii)
            {
                boundsOut[5] = (int)(startPoints[2] + *radii);
            }
            convTmp = (double)(int)*boundsOut;
            if (*endPoints - *radii < (float)(convTmp))
            {
                *boundsOut = (int)(*endPoints - *radii);
            }
            convTmp = (double)(int)boundsOut[3];
            if ((float)(convTmp) < *endPoints + *radii)
            {
                boundsOut[3] = (int)(*endPoints + *radii);
            }
            convTmp = (double)(int)boundsOut[1];
            if (endPoints[1] - *radii < (float)(convTmp))
            {
                boundsOut[1] = (int)(endPoints[1] - *radii);
            }
            convTmp = (double)(int)boundsOut[4];
            if ((float)(convTmp) < endPoints[1] + *radii)
            {
                boundsOut[4] = (int)(endPoints[1] + *radii);
            }
            convTmp = (double)(int)boundsOut[2];
            if (endPoints[2] - *radii < (float)(convTmp))
            {
                boundsOut[2] = (int)(endPoints[2] - *radii);
            }
            convTmp = (double)(int)boundsOut[5];
            if ((float)(convTmp) < endPoints[2] + *radii)
            {
                boundsOut[5] = (int)(endPoints[2] + *radii);
            }
            startPoints = startPoints + 3;
            endPoints = endPoints + 3;
            radii = radii + 1;
            pointCount = pointCount + -1;
        }
        while (pointCount != 0);
    }
    return;
}

u32* trackDolphin_getIntersectionDescriptorTable(u32* currentIndexOut)
{
    *currentIndexOut = DAT_803ddbec;
    return (u32*)&DAT_8038e8c4;
}

void trackDolphin_getCurrentTrackPoint(u32** trackPointOut)
{
    *trackPointOut = (u32*)&DAT_8038eaa4;
    return;
}

void trackDolphin_getCurrentIntersectionList(int* entryCountOut, u32* entryListOut)
{
    *entryCountOut = (int)(short)(&DAT_8038e8c8)[DAT_803ddbec * 0xc];
    *entryListOut = DAT_803ddbb0;
    return;
}

void trackDolphin_initIntersectionBuffers(void)
{
    int off;
    int remaining;

    if (DAT_803ddbb0 == 0)
    {
        DAT_803ddbb0 = FUN_80017830(0x16440, -0xff01);
        DAT_803ddbb4 = FUN_80017830(24000, -0xff01);
        DAT_803ddbb8 = (float*)FUN_80017830(0x4fb0, -0xff01);
        DAT_803ddbbc = FUN_80017830(3000, -0xff01);
        DAT_803ddbc8 = (int*)FUN_80017830(0x600, -0xff01);
    }
    off = 0;
    remaining = 4;
    do
    {
        *(u8*)((int)DAT_803ddbc8 + off + 0x14) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x2c) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x44) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x5c) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x74) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x8c) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0xa4) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0xbc) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0xd4) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0xec) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x104) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x11c) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x134) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x14c) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x164) = 0;
        *(u8*)((int)DAT_803ddbc8 + off + 0x17c) = 0;
        off = off + 0x180;
        remaining = remaining + -1;
    }
    while (remaining != 0);
    DAT_803ddbde = 0;
    DAT_803ddbdc = 0;
    DAT_803ddbce = 0;
    DAT_803ddbcf = 0;
    return;
}

void FUN_80064384(int param)
{
    int rowBase;
    int colBase;
    u32 scaled;
    u32 texAddr;
    u32 scale;
    u32 col;
    u32 colN;
    u32 row;
    int blockCount;

    texAddr = FUN_8001779c();
    row = 0;
    do
    {
        col = 0;
        rowBase = (row >> 2) * 0x100;
        colBase = (row & 3) * 8;
        scale = (row + param) * 0xff;
        blockCount = 0x10;
        do
        {
            scaled = scale;
            if (0x3fc0 < scale)
            {
                scaled = 0x3fc0;
            }
            *(char*)(texAddr + (col & 7) + (col >> 3) * 0x20 + colBase + rowBase) =
                (char)(scaled * col >> 0xc);
            colN = col + 1;
            scaled = scale;
            if (0x3fc0 < scale)
            {
                scaled = 0x3fc0;
            }
            *(char*)(texAddr + (colN & 7) + (colN >> 3) * 0x20 + colBase + rowBase) =
                (char)(scaled * colN >> 0xc);
            colN = col + 2;
            scaled = scale;
            if (0x3fc0 < scale)
            {
                scaled = 0x3fc0;
            }
            *(char*)(texAddr + (colN & 7) + (colN >> 3) * 0x20 + colBase + rowBase) =
                (char)(scaled * colN >> 0xc);
            colN = col + 3;
            scaled = scale;
            if (0x3fc0 < scale)
            {
                scaled = 0x3fc0;
            }
            *(char*)(texAddr + (colN & 7) + (colN >> 3) * 0x20 + colBase + rowBase) =
                (char)(scaled * colN >> 0xc);
            col = col + 4;
            blockCount = blockCount + -1;
        }
        while (blockCount != 0);
        row = row + 1;
    }
    while (row < 0x40);
    FUN_80017790(DAT_803ddc38 + 0x60, texAddr, 0);
    DAT_803ddc00 = param;
    return;
}

void doNothing_80062A50(void)
{
}

int return0_80060B90(void) { return 0x0; }

extern s8 gShadowFlag;
extern u8 mapBlockFlag;
void fn_800628CC(void) { gShadowFlag = 0x1; }
void setMapBlockFlag(void) { mapBlockFlag = 0x1; }

void* mapBlockFn_800606ec(int* obj, int idx) { return (char*)((int**)obj)[0x50 / 4] + idx * 0x14; }
void* fn_800606FC(int* obj, int idx) { return (char*)((int**)obj)[0x68 / 4] + idx * 0x1c; }
void* fn_8006070C(int* obj, int idx) { return (char*)((int**)obj)[0x64 / 4] + idx * 0x44; }

#pragma dont_inline on
void* fn_800606DC(int* obj, int idx) { return (char*)((int**)obj)[0x4c / 4] + idx * 8; }
#pragma dont_inline reset

extern u32 gSunFlareScissorX;
extern u32 gSunFlareScissorY;
extern u32 gSunFlareScissorWidth;
extern u32 gSunFlareScissorHeight;

void fn_80060490(u32* a, u32* b, u32* c, u32* d)
{
    *a = gSunFlareScissorX;
    *b = gSunFlareScissorY;
    *c = gSunFlareScissorWidth;
    *d = gSunFlareScissorHeight;
}

void setShadowFlag_803db658(s32 v)
{
    gShadowFlag = v;
}

extern u8 gActiveTrackBlockCount;
extern u32 gTrackTriangleBuffer;
extern u8 gTrackGridOrigin[];

typedef struct TrackBlockDescriptor
{
    void* object;
    s16 firstTriangle;
    u8 pad06[2];
    void* currentMatrix;
    void* currentCollisionMatrix;
    void* alternateMatrix;
    void* alternateCollisionMatrix;
} TrackBlockDescriptor;

extern TrackBlockDescriptor gTrackBlockDescriptors[];
#pragma dont_inline on
void* fn_80069944(u32* outVal)
{
    *outVal = gActiveTrackBlockCount;
    return gTrackBlockDescriptors;
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_80069958(void** out)
{
    *out = gTrackGridOrigin;
}
#pragma dont_inline reset

/* mapBlockFn_80060678 -- return top byte of obj[0x10]
 * (clrrwi 24 + srwi 24). */
u32 mapBlockFn_80060678(int* obj)
{
    return (*(u32*)&((GameObject*)obj)->anim.localPosY & 0xff000000) >> 24;
}

/* mapGetBlocks: write a fixed table base and an sbss u32 into two
 * out-pointers. */
extern u8 gMapBlockLayerTables[];
extern u32 lbl_803DCE9C;

void mapGetBlocks(void** outPtr, u32* outVal)
{
    *outPtr = gMapBlockLayerTables;
    *outVal = lbl_803DCE9C;
}

/* playerShadowFn_80062a30 -- if obj[0x64] non-NULL, clear bits 0x2020 in
 * its u32 at +0x30. */
void playerShadowFn_80062a30(int* obj)
{
    ObjModelState* p = ((GameObject*)obj)->anim.modelState;
    if (p == NULL) return;
    p->flags &= ~0x2020;
}

/* fn_80060668 -- extract bits 8-15 of obj[0x10] as a byte. */
#pragma dont_inline on
u32 fn_80060668(int* obj)
{
    u32 v = obj[4];
    v &= 0x00FF0000;
    return v >> 16;
}
#pragma dont_inline reset

/* fn_80062894 -- clear two shorts, toggle two bytes (1 - x), clear
 * two more bytes. */
extern s16 lbl_803DCEF6;
extern s16 lbl_803DCEFA;
extern s8 lbl_803DCEEA;
extern s8 lbl_803DCEEB;
extern u8 lbl_803DCEE9;
extern u8 lbl_803DCEE8;

void fn_80062894(void)
{
    lbl_803DCEF6 = 0;
    lbl_803DCEFA = 0;
    lbl_803DCEEA = (s8)(1 - lbl_803DCEEA);
    lbl_803DCEEB = (s8)(1 - lbl_803DCEEB);
    lbl_803DCEE9 = 0;
    lbl_803DCEE8 = 0;
}

/* fn_80069968 -- read s16 at gTrackBlockDescriptors[idx*0x18 + 4] into *out1, and
 * the sbss u32 gTrackTriangleBuffer into *out2. */
#pragma dont_inline on
void fn_80069968(s32* out1, u32* out2)
{
    TrackBlockDescriptor* descriptors = gTrackBlockDescriptors;
    *out1 = descriptors[gActiveTrackBlockCount].firstTriangle;
    *out2 = gTrackTriangleBuffer;
}
#pragma dont_inline reset

extern u8 lbl_803DCF4F;
extern u8 lbl_803DCF4D;

int fn_80065640(void)
{
    int r = 0;
    if ((s8)mapBlockFlag != 0 || (s8)lbl_803DCF4F != 0 || lbl_803DCF4D != 0) r = 1;
    return r;
}

extern int gMapDynamicSlots;

#define MAP_DYNAMIC_SLOT_COUNT 64

typedef struct MapDynamicSlot
{
    u32 object;
    u8 pad04[0x10];
    u8 cooldown;
    u8 pad15[3];
} MapDynamicSlot;

void objFn_80065604(void)
{
    u32 cur;
    int idx;
    s16 i;
    i = 0;
    idx = 0;
    do
    {
        u8* p = (u8*)(gMapDynamicSlots + idx);
        cur = p[20];
        if (cur != 0) p[20]--;
        idx += sizeof(MapDynamicSlot);
        i++;
    }
    while (i < MAP_DYNAMIC_SLOT_COUNT);
}

#pragma peephole on
#pragma optimization_level 1
void fn_80063368(int target)
{
    int zero, idx;
    s16 i;
    i = 0;
    idx = 0;
    zero = idx;
    for (; i < MAP_DYNAMIC_SLOT_COUNT; i++)
    {
        u32* p = (u32*)(gMapDynamicSlots + idx);
        if (*p == target)
        {
            ((MapDynamicSlot*)p)->cooldown = zero;
        }
        idx += sizeof(MapDynamicSlot);
    }
}
#pragma optimization_level reset
#pragma peephole reset

extern u8 lbl_803DCE06;
extern int gGlowLightList[];
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern char gViewFrustumPlanes[];

void queueGlowRender(ModelLightStruct* light)
{
    u8 i;
    int visible;
    u8 idx;
    f32 offsetZ;
    f32 offsetX;

    if (lbl_803DCE06 >= 100) return;

    i = 0;
    offsetZ = playerMapOffsetZ;
    offsetX = playerMapOffsetX;
    for (; i < 5; i++)
    {
        FrustumPlane* plane = (FrustumPlane*)(gViewFrustumPlanes + i * sizeof(FrustumPlane));
        f32 dot = light->worldY * plane->normalY
            + plane->normalX * (light->worldX - offsetX)
            + plane->normalZ * (light->worldZ - offsetZ)
            + plane->distance + lbl_803DEBCC;
        if (dot < lbl_803DEBCC)
        {
            visible = 0;
            goto check;
        }
    }
    visible = 1;
check:
    {
        u8 vis = visible;
        if (vis == 0 && light->glowAlpha == 0) return;
        if (vis == 0)
        {
            light->glowAlphaStep = -0x10;
        }
    }
    idx = lbl_803DCE06++;
    gGlowLightList[idx] = (int)light;
}

extern u8 lbl_803DCE98;

#pragma peephole on
#pragma optimization_level 1
void fn_80060BB0(void)
{
    char* arr;
    int zero;
    int innerOff;
    int byteOff;
    int i;
    int j;
    int* blk;

    i = 0;
    byteOff = 0;
    zero = byteOff;
    for (; i < lbl_803DCE98; i++)
    {
        blk = *(int**)((char*)lbl_803DCE9C + byteOff);
        if (blk != NULL)
        {
            j = 0;
            innerOff = 0;
            for (; j < (int)*(u8*)((char*)blk + 0xa1); j++)
            {
                int o;
                arr = *(char**)((char*)blk + 0x68);
                o = innerOff + 0x12;
                arr[o] = zero;
                innerOff += 0x1c;
            }
        }
        byteOff += 4;
    }
}
#pragma optimization_level reset
#pragma peephole reset

extern f32* lbl_803DCF38;
extern s16 gIntersectPointCount;

#pragma dont_inline on
int insertPoint(int val, s16* arr, f32 x, f32 y, f32 z)
{
    f32* p;
    f32* base;
    int i;
    int n;

    i = 0;
    p = base = lbl_803DCF38;
    n = gIntersectPointCount;
    for (; i < n; i++)
    {
        if (x == p[0] && y == p[1] && z == p[2])
        {
            s16* q = arr + 1;
            q[i << 1] = val;
            return i;
        }
        p += 3;
    }
    base[n * 3] = x;
    lbl_803DCF38[gIntersectPointCount * 3 + 1] = y;
    lbl_803DCF38[gIntersectPointCount * 3 + 2] = z;
    arr[gIntersectPointCount << 1] = val;
    arr[(gIntersectPointCount << 1) + 1] = -1;
    gIntersectPointCount++;
    return gIntersectPointCount - 1;
}
#pragma dont_inline reset

extern char sTrackIntersectFuncOverflowFormat[];
extern void debugPrintf(char* fmt, ...);
extern s16 gIntersectLineCount;
extern int lbl_803DCF34;
extern void memcpy(void* dst, void* src, int n);

void intersectModLineBuild(int* obj)
{
    s16 link[0xd48];
    int seg;
    int segCount;
    u8* sp;
    int li;
    int prev;

    mapBlockFlag = 1;
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
    segCount = *(u8*)((char*)obj + 0x5c);
    sp = *(u8**)&((GameObject*)obj)->anim.parent;
    for (seg = 0; seg < segCount; seg++, sp += 0x14)
    {
        u8* line;
        int i;
        if (gIntersectLineCount >= 0x5dc) break;
        line = (u8*)lbl_803DCF34 + gIntersectLineCount * 0x10;
        line[0] = sp[0xc];
        line[1] = sp[0xd];
        line[3] = sp[0xf];
        if ((*(s8*)(line + 3) & 0x3f) == 0x11)
        {
            *(s8*)(line + 3) &= ~0x3f;
            *(s8*)(line + 3) |= 2;
        }
        line[2] = sp[0xe];
        *(s8*)(line + 2) ^= 0x10;
        *(s16*)(line + 0xc) = *(s16*)(sp + 0x10);
        for (i = 0; i < 2; i++)
        {
            f32 x = (f32)(s16) * (s16*)(sp + i * 2 + 0);
            f32 y = (f32)(s16) * (s16*)(sp + i * 2 + 4);
            f32 z = (f32)(s16) * (s16*)(sp + i * 2 + 8);
            if (gIntersectPointCount < 0x6a4)
                *(s16*)(line + 4 + i * 2) = insertPoint(gIntersectLineCount, link, x, y, z);
        }
        gIntersectLineCount++;
    }
    {
        int off;
        for (li = 0, off = 0; li < gIntersectLineCount; li++, off += 0x10)
        {
            u8* L = (u8*)lbl_803DCF34 + off;
            int t0 = *(s16*)(L + 4) * 2;
            s16* e0 = &link[t0];
            s16* e1;
            if (e0[0] > -1 && e0[0] != li)
                *(s16*)(L + 8) = e0[0];
            else if (e0[1] > -1 && e0[1] != li)
                *(s16*)(L + 8) = e0[1];
            else
                *(s16*)(L + 8) = -1;
            {
                int t1 = *(s16*)(L + 6) * 2;
                e1 = &link[t1];
            }
            if (e1[0] > -1 && e1[0] != li)
                *(s16*)(L + 0xa) = e1[0];
            else if (e1[1] > -1 && e1[1] != li)
                *(s16*)(L + 0xa) = e1[1];
            else
                *(s16*)(L + 0xa) = -1;
        }
    }
    if (gIntersectLineCount * 0x10 + gIntersectPointCount * 0xc + 0x28 == 0)
        return;
    obj[0x34 / 4] = (int)mmAlloc(gIntersectLineCount * 0x10 + gIntersectPointCount * 0xc + 0x28, 0xffff00ff, 0);
    *(int*)((char*)obj + 0x3c) = *(int*)((char*)obj + 0x34) + gIntersectLineCount * 0x10;
    *(int*)((char*)obj + 0x38) = *(int*)((char*)obj + 0x3c) + gIntersectPointCount * 0xc;
    {
        int k;
        for (k = 0; k < 40; k++)
            ((u8*)*(int*)((char*)obj + 0x38))[k] = 0xff;
    }
    prev = -1;
    for (li = 0; li < gIntersectLineCount; li++)
    {
        u8* base = (u8*)lbl_803DCF34;
        s16 best = 0;
        int j;
        s16 grp;
        for (j = 0; j < gIntersectLineCount; j++)
        {
            if (((s8)base[j * 0x10 + 3] & 0x3f) < ((s8)base[best * 0x10 + 3] & 0x3f))
                best = j;
        }
        grp = (s16)((s8)base[best * 0x10 + 3] & 0x3f);
        if (grp >= 0x14)
        {
            grp = 1;
            debugPrintf(sTrackIntersectFuncOverflowFormat, 1);
        }
        if ((s16)grp != (s16)prev)
        {
            *(u8*)(*(int*)((char*)obj + 0x38) + grp * 2) = li;
            if (prev != -1)
                *(u8*)(*(int*)((char*)obj + 0x38) + prev * 2 + 1) = li;
            prev = grp;
        }
        {
            int m;
            for (m = 0; m < li; m++)
            {
                if (*(s16*)((u8*)*(int*)((char*)obj + 0x34) + m * 0x10 + 8) == (s16)best)
                    *(s16*)((u8*)*(int*)((char*)obj + 0x34) + m * 0x10 + 8) = li;
                if (*(s16*)((u8*)*(int*)((char*)obj + 0x34) + m * 0x10 + 0xa) == best)
                    *(s16*)((u8*)*(int*)((char*)obj + 0x34) + m * 0x10 + 0xa) = li;
            }
        }
        {
            int n;
            for (n = 0; n < gIntersectLineCount; n++)
            {
                if ((s8)((u8*)lbl_803DCF34)[n * 0x10 + 3] != 0x14)
                {
                    if ((s16)best == *(s16*)((u8*)lbl_803DCF34 + n * 0x10 + 8))
                        *(s16*)((u8*)lbl_803DCF34 + n * 0x10 + 8) = li;
                    if ((s16)best == *(s16*)((u8*)lbl_803DCF34 + n * 0x10 + 0xa))
                        *(s16*)((u8*)lbl_803DCF34 + n * 0x10 + 0xa) = li;
                }
            }
        }
        memcpy((char*)*(int*)((char*)obj + 0x34) + li * 0x10,
               (char*)lbl_803DCF34 + best * 0x10, 0x10);
        *(u8*)(lbl_803DCF34 + best * 0x10 + 3) = 0x14;
    }
    if ((s16)prev != -1)
        *(u8*)(*(int*)((char*)obj + 0x38) + prev * 2 + 1) = gIntersectLineCount;
    memcpy((void*)*(int*)((char*)obj + 0x3c), lbl_803DCF38, gIntersectPointCount * 0xc);
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
}

extern f32 CurrTiming_803DEC20;

void fn_800605F0(s16* in, f32* out)
{
    f32 t;

    out[0] = (f32)(s32)
    in[0] * (t = CurrTiming_803DEC20);
    out[1] = (f32)(s32)
    in[1] * t;
    out[2] = (f32)(s32)
    in[2] * t;
}

int fn_80060688(int obj, int type)
{
    int entry;
    int offset;
    int total;
    int i;
    int count;
    total = 0;
    offset = 0;
    count = *(u16*)(obj + 0x9a);
    for (i = 0; i < count; i++)
    {
        entry = *(int*)&((GameObject*)obj)->anim.modelInstance + offset;
        if (type == (int)((*(u32*)(entry + 0x10) & 0xff000000) >> 24))
        {
            total += *(u16*)(entry + 0x14) - *(u16*)entry;
        }
        offset += 0x14;
    }
    return total;
}

extern s16 lbl_803DCEF4;
extern s16 lbl_803DCEF8;
extern s16 lbl_803DCEFC;
extern s8 lbl_803DCEEC;
extern s8 lbl_803DCEED;
extern s8 lbl_803DCEEE;
extern int lbl_803DCF04;
extern int lbl_803DCF08;
extern int lbl_803DCF0C;
extern int lbl_803DCF10;
extern int lbl_803DCF14;
extern int lbl_803DCF18;
extern int lbl_803DCF1C;
extern int lbl_803DCF20;
extern int lbl_803DCF24;

void fn_80062808(void)
{
    int v;
    if ((s8)gShadowFlag == 0)
    {
        return;
    }
    lbl_803DCEF8 = 0;
    lbl_803DCEFC = 0;
    lbl_803DCEF4 = 0;
    lbl_803DCEEC = 1 - lbl_803DCEEC;
    lbl_803DCEED = 1 - lbl_803DCEED;
    lbl_803DCEEE = 1 - lbl_803DCEEE;
    v = (&lbl_803DCF24)[lbl_803DCEEC];
    lbl_803DCF08 = v;
    lbl_803DCEF4 = 0;
    lbl_803DCF10 = lbl_803DCF20;
    lbl_803DCF18 = lbl_803DCF1C;
    lbl_803DCF04 = v;
    lbl_803DCF14 = lbl_803DCF1C;
    lbl_803DCF0C = lbl_803DCF20;
}

void fn_80065574(int matchVal, int obj, int flag)
{
    int count;
    int i;
    int base;
    char* e;
    if ((u32)obj != 0)
    {
        base = *(int*)&((GameObject*)obj)->anim.modelInstance;
        e = *(char**)(base + 0x34);
        count = *(u8*)(base + 0x5c);
    }
    else
    {
        e = (char*)lbl_803DCF34;
        count = gIntersectLineCount;
    }
    if (flag != 0)
    {
        for (i = 0; i < count; i++)
        {
            if (*(s16*)(e + 0xc) == matchVal)
            {
                *(s8*)(e + 3) = (s8)(*(u8*)(e + 3) & ~0x40);
            }
            e += 0x10;
        }
    }
    else
    {
        for (i = 0; i < count; i++)
        {
            if (*(s16*)(e + 0xc) == matchVal)
            {
                *(s8*)(e + 3) = (s8)(*(u8*)(e + 3) | 0x40);
            }
            e += 0x10;
        }
    }
}

void MapBlock_init(int obj)
{
    int off;
    int i;
    if (*(u32*)&((GameObject*)obj)->anim.hitReactState != 0) *(int*)&((GameObject*)obj)->anim.hitReactState = obj + *(
        int*)&((GameObject*)obj)->anim.hitReactState;
    if (*(u32*)&((GameObject*)obj)->anim.placementData != 0) *(int*)&((GameObject*)obj)->anim.placementData = obj + *(
        int*)&((GameObject*)obj)->anim.placementData;
    if (*(u32*)&((GameObject*)obj)->anim.modelInstance != 0) *(int*)&((GameObject*)obj)->anim.modelInstance = obj + *(
        int*)&((GameObject*)obj)->anim.modelInstance;
    *(int*)(obj + 0x58) = obj + *(int*)(obj + 0x58);
    *(int*)&((GameObject*)obj)->anim.weaponDaTable = obj + *(int*)&((GameObject*)obj)->anim.weaponDaTable;
    *(int*)&((GameObject*)obj)->anim.eventTable = obj + *(int*)&((GameObject*)obj)->anim.eventTable;
    if (*(u32*)&((GameObject*)obj)->anim.hitVolumeBounds != 0) *(int*)&((GameObject*)obj)->anim.hitVolumeBounds = obj + *(int*)&((GameObject*)obj)->anim.hitVolumeBounds;
    if (*(u32*)&((GameObject*)obj)->anim.banks != 0) *(int*)&((GameObject*)obj)->anim.banks = obj + *(int*)&((GameObject
        *)obj)->anim.banks;
    if (*(u32*)&((GameObject*)obj)->anim.previousLocalPosX != 0) *(int*)&((GameObject*)obj)->anim.previousLocalPosX =
        obj + *(int*)&((GameObject*)obj)->anim.previousLocalPosX;
    *(int*)&((GameObject*)obj)->anim.dll = obj + *(int*)&((GameObject*)obj)->anim.dll;
    if (*(u32*)&((GameObject*)obj)->anim.modelState != 0) *(int*)&((GameObject*)obj)->anim.modelState = obj + *(int*)&((
        GameObject*)obj)->anim.modelState;
    for (i = 0, off = 0; i < *(u8*)(obj + 0xa1); i++)
    {
        *(int*)(*(int*)&((GameObject*)obj)->anim.dll + off) = obj + *(int*)(*(int*)&((GameObject*)obj)->anim.dll + off);
        off += 0x1c;
    }
}

extern int lbl_803DCE80;

void MapBlock_initHits(int obj, int index)
{
    int off;
    int i;
    int* table = (int*)lbl_803DCE80;
    int fileOff = table[index];
    int size = table[index + 1] - fileOff;
    int entry;
    if (size > 0)
    {
        *(void**)(obj + 0x70) = mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(0x28, *(void**)(obj + 0x70), fileOff, size);
    }
    *(u16*)(obj + 0x9c) = (u32)size / 20;
    for (i = 0, off = 0; i < *(u16*)(obj + 0x9c); i++)
    {
        entry = *(int*)&((GameObject*)obj)->anim.textureSlots + off;
        if (*(s16*)(entry + 0) < 0 || *(s16*)(entry + 2) < 0 ||
            *(s16*)(entry + 0) > 0x280 || *(s16*)(entry + 2) > 0x280)
        {
            *(u8*)(entry + 0xf) = 0x40;
        }
        entry = *(int*)&((GameObject*)obj)->anim.textureSlots + off;
        if (*(s16*)(entry + 8) < 0 || *(s16*)(entry + 0xa) < 0 ||
            *(s16*)(entry + 8) > 0x280 || *(s16*)(entry + 0xa) > 0x280)
        {
            *(u8*)(entry + 0xf) = 0x40;
        }
        off += 0x14;
    }
    *(int*)&((GameObject*)obj)->anim.hitVolumeTransforms = 0;
    *(u16*)(obj + 0x9e) = 0;
    *(u16*)&((GameObject*)obj)->anim.rotZ = *(u16*)&((GameObject*)obj)->anim.rotZ & ~0x40;
}

extern int lbl_803DCEB0;
extern int lbl_803DCDE4;
extern void checkLoadBlock(int v, int* outA, int* outB);
extern int loadAndDecompressDataFile(int id, void* buf, int blockOff, int len, int a, int b, int c);

void* MapBlock_loadFromFile(int blockId)
{
    int compressedLen;
    int decompressedSize;
    void* buf;
    int blockOff = 0;
    int* table;
    int tableEntry;
    if (blockId > lbl_803DCEB0)
    {
        goto ret0a;
    }
    table = (int*)lbl_803DCDE4;
    if (table != 0)
    {
        tableEntry = table[blockId];
        if (tableEntry != -1)
        {
            if (tableEntry == 0 && table[blockId + 1] == 0)
            {
                goto ret0b;
            }
            blockOff = tableEntry;
            checkLoadBlock(tableEntry, &compressedLen, &decompressedSize);
        }
    }
    goto cont;
ret0b:
    return 0;
ret0a:
    return 0;
cont:
    if (compressedLen <= 0)
    {
        return 0;
    }
    if (decompressedSize > 0x32000)
    {
        return 0;
    }
    buf = mmAlloc(decompressedSize, 5, 0);
    if (buf == 0)
    {
        return 0;
    }
    loadAndDecompressDataFile(0x25, buf, blockOff, compressedLen, 0, 0, 0);
    return buf;
}

extern int mapTextureOverrideAcquire(int tex, int value, int type);

void MapBlock_initShaders(int obj)
{
    char* p;
    int block;
    int i;
    int j;
    int v;
    int outerOff;
    for (i = 0, outerOff = 0; i < *(u8*)(obj + 0xa2); i++)
    {
        block = *(int*)&((GameObject*)obj)->anim.modelState + outerOff;
        p = (char*)block;
        for (j = 0; j < *(u8*)(block + 0x41); j++)
        {
            v = *(int*)&((ObjModelState*)p)->overrideWorldPosY;
            if (v != -1)
            {
                *(int*)&((ObjModelState*)p)->overrideWorldPosY = ((int*)*(int*)&((GameObject*)obj)->anim.hitReactState)[v];
                v = *(u8*)(p + 0x29);
                if ((u32)v != 0u)
                {
                    mapTextureOverrideAcquire(*(int*)&((ObjModelState*)p)->overrideWorldPosY, 0, v);
                }
            }
            else
            {
                *(int*)&((ObjModelState*)p)->overrideWorldPosY = 0;
            }
            *(u8*)(p + 0x2a) = 0xff;
            p += 8;
        }
        v = *(int*)(block + 0x34);
        if (v != -1)
        {
            *(int*)(block + 0x34) = ((int*)*(int*)&((GameObject*)obj)->anim.hitReactState)[v];
        }
        else
        {
            *(int*)(block + 0x34) = 0;
        }
        outerOff += 0x44;
    }
}

extern int gIntersectLineIndexTable;

void mapInitFn_80069990(void)
{
    int i;
    int off;
    if (gTrackTriangleBuffer == 0)
    {
        gTrackTriangleBuffer = (u32)mmAlloc(0x16440, 0xffff00ff, 0);
        lbl_803DCF34 = (int)mmAlloc(0x5dc0, 0xffff00ff, 0);
        lbl_803DCF38 = mmAlloc(0x4fb0, 0xffff00ff, 0);
        gIntersectLineIndexTable = (int)mmAlloc(0xbb8, 0xffff00ff, 0);
        gMapDynamicSlots = (int)mmAlloc(0x600, 0xffff00ff, 0);
    }
    off = 0;
    for (i = 0; i < 4; i++)
    {
        int j;
        for (j = 0; j < 16; j++)
        {
            ((MapDynamicSlot*)(gMapDynamicSlots + off + j * sizeof(MapDynamicSlot)))->cooldown = 0;
        }
        off += sizeof(MapDynamicSlot) * 16;
    }
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
    mapBlockFlag = 0;
    lbl_803DCF4F = 0;
}

void fn_8006058C(short* out, float* vec)
{
    int yScaled;
    int zScaled;

    yScaled = (int)(lbl_803DEC50 * vec[1]);
    zScaled = (int)(lbl_803DEC50 * vec[2]);
    *out = (short)(int)(lbl_803DEC50 * *vec);
    out[1] = yScaled;
    out[2] = zScaled;
}

#pragma dont_inline on
void vecGetRanges(f32* pts, f32* base, f32 scale, int* out)
{
    int i;

    out[0] = 0x7fffffff;
    out[3] = 0x80000000;
    out[1] = 0x7fffffff;
    out[4] = 0x80000000;
    out[2] = 0x7fffffff;
    out[5] = 0x80000000;
    for (i = 0; i < 8; i++)
    {
        f32 x = scale * pts[0] + base[0];
        f32 y = scale * pts[1] + base[1];
        f32 z = scale * pts[2] + base[2];
        if (x < out[0]) out[0] = x;
        if (x > out[3]) out[3] = x;
        if (y < out[1]) out[1] = y;
        if (y > out[4]) out[4] = y;
        if (z < out[2]) out[2] = z;
        if (z > out[5]) out[5] = z;
        pts += 3;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
int objShadowFn_80062378(void* obj, u8 param)
{
    int lo;
    int hi;
    f32 inv;
    void* p;

    p = ((GameObject*)obj)->anim.modelInstance;
    if (((ObjDef*)p)->renderFlags & 0x4)
    {
        lo = 1000;
        hi = 2000;
    }
    else
    {
        lo = 400;
        hi = 500;
    }
    inv = (Camera_DistanceToCurrentViewPosition(((GameObject*)obj)->anim.worldPosX,
                                                ((GameObject*)obj)->anim.worldPosY,
                                                ((GameObject*)obj)->anim.worldPosZ) -
            lo) /
        (f32)(hi - lo);
    if (inv < 0.0f)
    {
        inv = 0.0f;
    }
    else if (inv > 1.0f)
    {
        inv = 1.0f;
    }
    inv = 1.0f - inv;
    {
        int n = (int)((f32)param * inv);
        return (n * (*(u8*)((char*)obj + 0x37) + 1)) >> 8;
    }
}
#pragma dont_inline reset

int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e)
{
    void** arr;
    int n;
    int i;
    f32 best;
    f32 cur;

    n = hitDetectFn_80065e50(a, b, val, d, &arr, 0, e);
    if (n != 0)
    {
        void** arrp;
        best = val - *(f32*)arr[0];
        arrp = arr + 1;
        for (i = 1; i < n; i++, arrp++)
        {
            cur = val - *(f32*)*arrp;
            if (cur >= *(f32*)&__AR_Callback)
            {
                if (best < *(f32*)&__AR_Callback || cur < best)
                {
                    best = cur;
                }
            }
        }
        if (best >= __AR_Callback)
        {
            *out = best;
            return 1;
        }
        *out = __AR_Callback;
        return 0;
    }
    *out = __AR_Callback;
    return 0;
}

int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e)
{
    void** arr;
    int n;
    int i;
    int bestIdx;
    f32 best;
    f32 cur;

    n = hitDetectFn_80065e50(a, b, val, d, &arr, 0, e);
    if (n != 0)
    {
        cur = val - *(f32*)arr[0];
        cur = cur >= __AR_Callback ? cur : -cur;
        best = cur;
        bestIdx = 0;
        for (i = 1; i < n; i++)
        {
            cur = val - *(f32*)arr[i];
            cur = cur >= __AR_Callback ? cur : -cur;
            if (cur < best)
            {
                best = cur;
                bestIdx = i;
            }
        }
        *out = val - *(f32*)arr[bestIdx];
        return 0;
    }
    *out = __AR_Callback;
    return 1;
}

#pragma dont_inline on
int fn_80065768(int a, f32 b, f32 val, f32 d, f32* out1, f32* out2, int f)
{
    void** arr;
    int n;
    int i;
    int bestIdx;
    f32 best;
    f32 cur;

    n = hitDetectFn_80065e50(a, b, val, d, &arr, 0, f);
    if (n != 0)
    {
        cur = val - *(f32*)arr[0];
        if (cur >= __AR_Callback) {} else { cur = -cur; }
        best = cur;
        bestIdx = 0;
        for (i = 1; i < n; i++)
        {
            cur = val - *(f32*)arr[i];
            cur = cur >= *(f32*)&__AR_Callback ? cur : -cur;
            if (cur < best)
            {
                best = cur;
                bestIdx = i;
            }
        }
        *out1 = val - *(f32*)arr[bestIdx];
        out2[0] = ((f32*)arr[bestIdx])[1];
        out2[1] = ((f32*)arr[bestIdx])[2];
        out2[2] = ((f32*)arr[bestIdx])[3];
        return 0;
    }
    *out1 = __AR_Callback;
    return 1;
}
#pragma dont_inline reset

int findSurfaceInYRange(int a, f32 b, f32 lo, f32 d, f32 hi, f32* out1, int* out2)
{
    void** arr;
    int n;
    int i;

    if (lo > hi)
    {
        f32 t = hi;
        hi = lo;
        lo = t;
    }
    n = hitDetectFn_80065e50(a, b, lo, d, &arr, 0, 1);
    *out1 = lo;
    *out2 = 0;
    for (i = 0; i < n; i++)
    {
        void* elem = arr[i];
        if (*(s8*)((char*)elem + 0x14) == 14)
        {
            continue;
        }
        if (lo < *(f32*)elem && hi > *(f32*)elem)
        {
            *out2 = *(int*)((char*)arr[i] + 0x10);
            *out1 = *(f32*)arr[i];
            return (((f32*)arr[i])[2] < __AR_Size) + 1;
        }
    }
    return 0;
}

void* shadowInit(int* obj, int size)
{
    int rounded;
    ObjModelState* modelState;
    s16 texId;

    rounded = roundUpTo4(size);
    *(int*)&((ObjAnimComponent*)obj)->modelState = rounded;
    modelState = ((ObjAnimComponent*)obj)->modelState;
    texId = ((ObjAnimComponent*)obj)->modelInstance->shadowTextureId;
    if (texId != -1 && ((ObjAnimComponent*)obj)->modelInstance->shadowType != 2)
    {
        modelState->shadowTexture = (void*)textureLoad(-texId, 0);
    }
    else if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & 0x4)
    {
        modelState->shadowTexture = (void*)textureAlloc512();
    }
    else if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & 0x2)
    {
        modelState->shadowTexture = NULL;
        modelState->shadowWorkBuffer = NULL;
    }
    else
    {
        modelState->shadowTexture = (void*)textureFn_8006c5c4();
    }
    if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 1)
    {
        modelState->shadowRenderResource = NULL;
    }
    else
    {
        modelState->shadowRenderResource = (void*)-1;
    }
    modelState->shadowScale = *(f32*)((ObjAnimComponent*)obj)->modelInstance;
    modelState->shadowModelScale = *(f32*)((char*)((ObjAnimComponent*)obj)->modelInstance + 0x88);
    modelState->shadowOffsetX = gShadowOffsetX;
    modelState->shadowOffsetY = gShadowOffsetY;
    modelState->shadowOffsetZ = gShadowOffsetZ;
    modelState->shadowAlphaStep = 0x4000;
    modelState->flags = OBJ_MODEL_STATE_SHADOW_VISIBLE;
    modelState->pad38[0] = 0x19;
    modelState->pad38[1] = 0x4b;
    modelState->shadowTintA = 0x96;
    modelState->shadowTintB = 0x64;
    gShadowFlag = 1;
    return (char*)rounded + 0x44;
}

int fn_800626C8(int* obj, int delta)
{
    ObjModelState* modelState;
    s16* alphaStep;
    f32 f31;
    int v;

    modelState = ((ObjAnimComponent*)obj)->modelState;
    alphaStep = &modelState->shadowAlphaStep;
    if (modelState->flags & OBJ_MODEL_STATE_SHADOW_FADE_OUT)
    {
        *alphaStep = *alphaStep - (delta << 9);
        if (*alphaStep <= 0)
        {
            *alphaStep = 0;
        }
        if (*alphaStep == 0)
        {
            modelState->shadowCastSlot = NULL;
            return 0;
        }
    }
    else if (!(modelState->flags & OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD))
    {
        *alphaStep = *alphaStep + (delta << 9);
        if (*alphaStep >= 0x4000)
        {
            *alphaStep = 0x4000;
        }
    }
    f31 = lbl_803DEC90[0] * (f32) * alphaStep;
    f31 = lbl_803DB654 * f31;
    {
        f32 tint = objShadowFn_80062378(obj, modelState->shadowTintA);
        v = (s16)(int)(tint * f31);
    }
    if (v > 0xff)
    {
        v = 0xff;
    }
    else if (v < 0)
    {
        v = 0;
    }
    return v & 0xff;
}

#pragma optimization_level 3
void fn_80069EB8(int param)
{
    u8* cache;
    int blk;
    u32 j;

    cache = getCache();
    for (blk = 0; (u32)blk < 0x40; blk++)
    {
        int hi, mid;
        u32 scaled;
        j = 0;
        hi = ((u32)blk >> 2) << 8;
        mid = (blk & 3) << 3;
        scaled = (blk + param) * 0xff;
        for (; j < 0x40; j++)
        {
            int idx = (j & 7) + ((j >> 3) << 5) + mid + hi;
            u32 s = scaled;
            if (s > 0x3fc0)
            {
                s = 0x3fc0;
            }
            cache[idx] = (s * j) >> 12;
        }
    }
    memcpyToCache((void*)(lbl_803DCFB8 + 0x60), cache, 0);
    lbl_803DCF80 = param;
}
#pragma optimization_level 4

typedef struct AngleXf
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad6;
    f32 scale;
    f32 tx;
    f32 ty;
    f32 tz;
} AngleXf;

#pragma dont_inline on
void fn_80061094(f32* vec, f32* out, f32 scale)
{
    AngleXf xf;
    f64 ax;
    f64 az;
    int i;
    int rotY;

    xf.tx = 0.0f;
    xf.ty = 0.0f;
    xf.tz = 0.0f;
    xf.scale = 1.0f;
    xf.rotZ = 0;
    ax = __fabs(vec[0]);
    az = __fabs(vec[2]);
    if (ax > az)
    {
        rotY = (u16)getAngle(ax, vec[1]);
    }
    else
    {
        rotY = (u16)getAngle(az, vec[1]);
    }
    xf.rotY = rotY;
    if (xf.rotY > 0x2000)
    {
        xf.rotY = 0x2000;
    }
    xf.rotX = getAngle(vec[0], vec[2]);
    for (i = 0; i < 8; i++)
    {
        out[i * 3 + 0] = lbl_8038D7DC[i * 3 + 0];
        if (lbl_8038D7DC[i * 3 + 1] > 0.0f)
        {
            out[i * 3 + 1] = lbl_8038D7DC[i * 3 + 1];
        }
        else
        {
            out[i * 3 + 1] = scale * lbl_8038D7DC[i * 3 + 1];
        }
        out[i * 3 + 2] = lbl_8038D7DC[i * 3 + 2];
        vecRotateZXY(&xf, &out[i * 3]);
    }
}
#pragma dont_inline reset

void skyFn_80062a54(f32 a, f32 b, f32 c, int param)
{
    f32 vec[3];
    f32 dot;
    f32 mag;

    vec[0] = a;
    vec[1] = b;
    vec[2] = c;
    PSVECNormalize(vec, vec);
    gSunMagnitude = param;
    gShadowOffsetX = a * param;
    gShadowOffsetY = b * param;
    lbl_803DB654 = lbl_803DEC68;
    if (gShadowOffsetY < lbl_803DEC94)
    {
        gShadowOffsetY = lbl_803DEC94;
    }
    gShadowOffsetZ = c * param;
    dot = vec[0] * gPrevSunDir[0] + vec[1] * gPrevSunDir[1] + vec[2] * gPrevSunDir[2];
    mag = (gPrevSunDir[0] * gPrevSunDir[0] + gPrevSunDir[1] * gPrevSunDir[1] +
        gPrevSunDir[2] * gPrevSunDir[2]) *
    (vec[0] * vec[0] + vec[1] * vec[1] + vec[2] * vec[2]);
    if (mag != lbl_803DEC58)
    {
        mag = sqrtf(mag);
    }
    if (mag != lbl_803DEC58)
    {
        gSunDotCos = dot / mag;
        if (gSunDotCos < 0.0f)
        {
            gSunDotCos = gSunDotCos * __AR_init_flag;
        }
        if (gSunDotCos <= __AR_BlockLength)
        {
            gSunDirChanged = 1;
        }
    }
    if (gSunDirChanged != 0)
    {
        gPrevSunDir[0] = vec[0];
        gPrevSunDir[1] = vec[1];
        gPrevSunDir[2] = vec[2];
        gSunDirChanged = 0;
    }
    gShadowFlag = 1;
}

#pragma opt_strength_reduction off
int fn_80061DD8(void* obj, void* u1, void* u2, int count, f32* outBase, f32* outPtr, f32* input, int limit)
{
    int n = 0;
    int outCount = 0;
    ObjModelState* modelState = ((ObjAnimComponent*)obj)->modelState;

    gShadowVisibleCount = 0;
    for (; n < count; n++)
    {
        int vis = 1;
        int i = n * 3;
        f32 dot = modelState->shadowOffsetX * input[0] +
            modelState->shadowOffsetY * input[1] +
            modelState->shadowOffsetZ * input[2];
        if (dot < 0.0f)
        {
            vis = -1;
        }
        if (vis == 1)
        {
            gShadowVisibleCount++;
            outPtr[0] = *(f32*)((char*)outBase + i * 0xc + 0);
            outPtr[1] = *(f32*)((char*)outBase + i * 0xc + 4);
            outPtr[2] = *(f32*)((char*)outBase + i * 0xc + 8);
            if (++outCount >= limit)
            {
                return 0;
            }
            outPtr[3] = *(f32*)((char*)outBase + (i + 1) * 0xc + 0);
            outPtr[4] = *(f32*)((char*)outBase + (i + 1) * 0xc + 4);
            outPtr[5] = *(f32*)((char*)outBase + (i + 1) * 0xc + 8);
            if (++outCount >= limit)
            {
                return 0;
            }
            outPtr[6] = *(f32*)((char*)outBase + (i + 2) * 0xc + 0);
            outPtr[7] = *(f32*)((char*)outBase + (i + 2) * 0xc + 4);
            outPtr[8] = *(f32*)((char*)outBase + (i + 2) * 0xc + 8);
            outPtr += 9;
            if (++outCount >= limit)
            {
                return 0;
            }
        }
        input += 5;
    }
    return gShadowVisibleCount > 0;
}
#pragma opt_strength_reduction reset

void fn_8006135C(s16* out, void* obj)
{
    f32 dist;
    f32 b[3];
    f32 c[3];
    f32 a[3];
    f64 d;
    f32 scale;
    f32 z;
    f32 s;
    f32 nd;

    if (fn_80065768((int)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, &dist, a, 0) != 0)
    {
        goto fail;
    }
    PSVECNormalize(a, a);
    b[0] = lbl_803DEC68;
    b[1] = lbl_803DEC58;
    b[2] = lbl_803DEC58;
    d = __fabs(PSVECDotProduct(a, b));
    if (d >= lbl_803DEC6C)
    {
        b[0] = lbl_803DEC58;
        b[2] = lbl_803DEC68;
    }
    PSVECCrossProduct(a, b, c);
    PSVECCrossProduct(c, a, b);
    PSVECNormalize(b, b);
    PSVECNormalize(c, c);
    scale = lbl_803DEC70 * ((ObjAnimComponent*)obj)->modelState->shadowScale;
    PSVECScale(b, b, scale);
    PSVECScale(c, c, scale);
    nd = -dist;
    s = lbl_803DEC74;
    z = lbl_803DEC58;
    out[0] = (s * ((z - b[0]) - c[0]));
    out[1] = (s * ((nd - b[1]) - c[1]));
    out[2] = (s * ((z - b[2]) - c[2]));
    out[3] = (s * ((z + b[0]) - c[0]));
    out[4] = (s * ((nd + b[1]) - c[1]));
    out[5] = (s * ((z + b[2]) - c[2]));
    out[6] = (s * (c[0] + (z + b[0])));
    out[7] = (s * (c[1] + (nd + b[1])));
    out[8] = (s * (c[2] + (z + b[2])));
    out[9] = (s * (c[0] + (z - b[0])));
    out[10] = (s * (c[1] + (nd - b[1])));
    out[11] = (s * (c[2] + (z - b[2])));
    *(u8*)((char*)out + 0x18) = 1;
    return;
fail:
    *(u8*)((char*)out + 0x18) = 0xff;
}

void hitDetect_calcSweptSphereBounds(int* boundsOut, f32* startPoints, f32* endPoints, f32* radii, int pointCount)
{
    int i;

    boundsOut[0] = 1000000;
    boundsOut[3] = -1000000;
    boundsOut[1] = 1000000;
    boundsOut[4] = -1000000;
    boundsOut[2] = 1000000;
    boundsOut[5] = -1000000;
    for (i = pointCount; i != 0; i--)
    {
        if (startPoints[0] - radii[0] < boundsOut[0]) boundsOut[0] = (int)(startPoints[0] - radii[0]);
        if (startPoints[0] + radii[0] > boundsOut[3]) boundsOut[3] = (int)(startPoints[0] + radii[0]);
        if (startPoints[1] - radii[0] < boundsOut[1]) boundsOut[1] = (int)(startPoints[1] - radii[0]);
        if (startPoints[1] + radii[0] > boundsOut[4]) boundsOut[4] = (int)(startPoints[1] + radii[0]);
        if (startPoints[2] - radii[0] < boundsOut[2]) boundsOut[2] = (int)(startPoints[2] - radii[0]);
        if (startPoints[2] + radii[0] > boundsOut[5]) boundsOut[5] = (int)(startPoints[2] + radii[0]);
        if (endPoints[0] - radii[0] < boundsOut[0]) boundsOut[0] = (int)(endPoints[0] - radii[0]);
        if (endPoints[0] + radii[0] > boundsOut[3]) boundsOut[3] = (int)(endPoints[0] + radii[0]);
        if (endPoints[1] - radii[0] < boundsOut[1]) boundsOut[1] = (int)(endPoints[1] - radii[0]);
        if (endPoints[1] + radii[0] > boundsOut[4]) boundsOut[4] = (int)(endPoints[1] + radii[0]);
        if (endPoints[2] - radii[0] < boundsOut[2]) boundsOut[2] = (int)(endPoints[2] - radii[0]);
        if (endPoints[2] + radii[0] > boundsOut[5]) boundsOut[5] = (int)(endPoints[2] + radii[0]);
        startPoints += 3;
        endPoints += 3;
        radii += 1;
    }
}

extern int shouldDrawShadows(void);
extern void hitDetectFn_800691c0(int* obj, int* ranges, int a, int b);

void trackDolphin_buildShadowVolumePlanes(int* obj, void* buf48, void* bufA8);

extern u8 gShadowDrawScratch[];
extern int gShadowVolumeBuffer;
extern int lbl_803DCEE0;
extern int lbl_803DCEE4;
extern s16 lbl_803DCEF0;

int objShadowFn_80062498(int* obj, int param2)
{
    ObjModelState* modelState;
    u8* cache;
    f32 yOff;
    int idxOut = 0;
    int drawScratch;
    u32* vtx;
    int alphaOut = 0;
    int alpha;
    u32 handle;
    f32 vec[3];
    f32 base[3];
    int ranges[6];
    u8 buf48[96];
    u8 bufA8[304];

    cache = getCache();
    modelState = ((ObjAnimComponent*)obj)->modelState;
    if (shouldDrawShadows() == 0)
    {
        ((ObjAnimComponent*)obj)->modelState->shadowCastSlot = NULL;
        return 0;
    }

    handle = (u32)modelState->shadowRenderResource;
    if (handle == 0 || handle == 0xFFFFFFFF)
    {
        vec[0] = modelState->shadowOffsetX;
        vec[1] = modelState->shadowOffsetY;
        vec[2] = modelState->shadowOffsetZ;
        fn_80061094(vec, (f32*)buf48, modelState->shadowModelScale);

        {
            void* p54 = ((GameObject*)obj)->anim.hitReactState;
            if (p54 != NULL)
            {
                yOff = (f32)((int)((ObjHitsPriorityState*)p54)->primaryCapsuleOffsetB / 2);
            }
            else
            {
                yOff = lbl_803DEC58;
            }
        }

        base[0] = ((GameObject*)obj)->anim.worldPosX;
        base[1] = ((GameObject*)obj)->anim.worldPosY + yOff;
        base[2] = ((GameObject*)obj)->anim.worldPosZ;
        vecGetRanges((f32*)buf48, base, modelState->shadowScale, ranges);

        hitDetectFn_800691c0(obj, ranges, 0x81, 0);
        fn_80069958((void**)&vtx);
        fn_80069968((s32*)&idxOut, (u32*)&alphaOut);

        alpha = alphaOut;
        idxOut = fn_80060C14(obj, alpha,
                             gShadowDrawScratch, gShadowVolumeBuffer, idxOut,
                             (f32)(int)vtx[0], (f32)(int)vtx[2], param2,
                             modelState->flags & 0x40000);
        lbl_803DCEE0 = alpha;
        lbl_803DCEF0 = idxOut;
        lbl_803DCEE4 = (int)vtx;
        trackDolphin_buildShadowVolumePlanes(obj, buf48, bufA8);
        fn_80061DD8(obj, buf48, bufA8, idxOut, (f32*)gShadowVolumeBuffer, (f32*)cache,
                    (f32*)gShadowDrawScratch, 0x555);
    }
    objDrawFn_80061f0c(cache, modelState, obj, gShadowVisibleCount, &drawScratch, buf48, yOff);
    return 0;
}

extern int mapLoadBlocksFn_800685cc(int base, int x0, int y0, int z0, int x1, int y1, int z1, int a, int b);
extern int fn_80067B84(int cur, TrackBlockDescriptor* desc, int model, int flags, f32 c, f32 x0, f32 y0, f32 z0, f32 x1,
                       f32 y1, f32 z1);
extern u16 modelFileHeaderGetCullDistance(u8* modelFile);
extern u32 gTrackTriangleBufferEnd;
extern s16 gTrackTriangleCount;
extern f32 lbl_803DECC4;

void hitDetectFn_800691c0(int* obj, int* ranges, int a, int b)
{
    f32 f31 = (f32)(ranges[0] - 5);
    f32 f30 = (f32)(ranges[3] + 5);
    f32 f29 = (f32)(ranges[1] - 5);
    f32 f28 = (f32)(ranges[4] + 5);
    f32 f27 = (f32)(ranges[2] - 5);
    f32 f26 = (f32)(ranges[5] + 5);
    TrackBlockDescriptor* desc;
    TrackBlockDescriptor* descEnd;
    int cur;
    int masked;

    gTrackBlockDescriptors[0].object = NULL;
    gTrackBlockDescriptors[0].firstTriangle = 0;
    desc = &gTrackBlockDescriptors[1];
    descEnd = &gTrackBlockDescriptors[20];
    gTrackTriangleBufferEnd = gTrackTriangleBuffer + 0x16440;
    masked = a & 0xffff;
    if ((masked & 0x10) != 0)
    {
        cur = gTrackTriangleBuffer;
    }
    else
    {
        cur = mapLoadBlocksFn_800685cc(gTrackTriangleBuffer, f31, f29, f27,
                                       f30, f28, f26, a, b);
    }
    if ((u32)cur < gTrackTriangleBufferEnd && (masked & 1) && obj != NULL)
    {
        int count;
        s16 i;
        int flag80 = masked & 0x80;
        ObjAnimComponent** resetObjects = ObjHitReact_GetResetObjects(&count);
        for (i = 0; i < count; i++, resetObjects++)
        {
            ObjAnimComponent* resetObj = *resetObjects;
            ObjHitsPriorityState* hitState;
            ObjHitboxTransformState* transformState;
            int n;
            int* model;
            int hdr;
            f32 r, c;

            if (flag80 && (resetObj->modelInstance->flags & 0x01000000)) continue;
            hitState = (ObjHitsPriorityState*)resetObj->hitReactState;
            if (hitState == NULL) continue;
            transformState = ((ObjHitbox*)resetObj)->transformState;
            if (transformState == NULL) continue;
            if (transformState->resetFrames != 0) continue;
            if (transformState->pad10E != 0) continue;
            model = (int*)resetObj->banks[(s8)hitState->stateIndex];
            if (model == NULL) continue;
            hdr = *(int*)model;
            if (*(u16*)(hdr + 0xf0) == 0) continue;
            r = (f32)(u32)(u16)
            modelFileHeaderGetCullDistance((void*)hdr);
            c = resetObj->worldPosX;
            if (f30 < c - r) continue;
            if (f31 > c + r) continue;
            c = resetObj->worldPosY;
            if (f28 < c - r) continue;
            if (f29 > c + r) continue;
            c = resetObj->worldPosZ;
            if (f26 < c - r) continue;
            if (f27 > c + r) continue;

            desc->currentCollisionMatrix =
                ((ObjHitbox*)resetObj)->transformState->matrices[((ObjHitbox*)resetObj)->transformState->activeMatrixIndex + 2];
            desc->currentMatrix =
                ((ObjHitbox*)resetObj)->transformState->matrices[((ObjHitbox*)resetObj)->transformState->activeMatrixIndex];
            desc->alternateCollisionMatrix =
                ((ObjHitbox*)resetObj)->transformState->matrices[(((ObjHitbox*)resetObj)->transformState->activeMatrixIndex ^ 1) + 2];
            desc->alternateMatrix =
                ((ObjHitbox*)resetObj)->transformState->matrices[((ObjHitbox*)resetObj)->transformState->activeMatrixIndex ^ 1];

            desc->firstTriangle = (s16)((cur - (int)gTrackTriangleBuffer) / 0x4c);
            desc->object = resetObj;
            cur = fn_80067B84(cur, desc, (int)model, a & 0xff, lbl_803DECC4,
                              f31, f29, f27, f30, f28, f26);
            desc++;
            if ((u32)cur >= gTrackTriangleBufferEnd) break;
            if (desc >= descEnd) break;
        }
    }
    gTrackTriangleCount = (s16)((cur - (int)gTrackTriangleBuffer) / 0x4c);
    gActiveTrackBlockCount = (u8)(desc - gTrackBlockDescriptors);
    desc->firstTriangle = gTrackTriangleCount;
}

extern void PSMTXMultVecArray(void* m, void* src, void* dst, u32 count);

int fn_80060C14(int* obj, int p4, void* p5, int p6, int p7, f32 a, f32 b, int p8, int p9)
{
    int j;
    f32 lm[12];
    u8* d = fn_80069944((u32*)&j);
    u8* end = d + j * 0x18;
    int grp = 0;
    int outOff = 0;
    int total;

    j = 0;
    total = 0;
    p9 = p9 ? 4 : 8;
    for (; d < end; d += 0x18)
    {
        u32 id = *(u32*)d;
        if (id == 0 || id == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            f32 fx = ((GameObject*)obj)->anim.localPosX;
            f32 fz = ((GameObject*)obj)->anim.localPosZ;
            f32* outA;

            if (id == 0)
            {
                fx -= a;
                fz -= b;
            }
            j = (s16) * (s16*)((char*)d + 4);
            outA = (f32*)((char*)p5 + outOff);
            while (j < (s16) * (s16*)((char*)d + 0x1c) && grp < 0x4b0 && total < 0xe10)
            {
                if (p9 & (s8) * (u8*)((char*)p4 + j * 0x4c + 0x49))
                {
                    ((TrackP6Entry*)p6)->relX0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x10)) - fx;
                    ((TrackP6Entry*)p6)->relY0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x16)) - ((GameObject*)obj)
                        ->anim.localPosY;
                    ((TrackP6Entry*)p6)->relZ0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1c)) - fz;
                    ((TrackP6Entry*)p6)->relX1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x12)) - fx;
                    ((TrackP6Entry*)p6)->relY1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x18)) - ((GameObject*)obj)
                        ->anim.localPosY;
                    ((TrackP6Entry*)p6)->relZ1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1e)) - fz;
                    ((TrackP6Entry*)p6)->relX2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x14)) - fx;
                    ((TrackP6Entry*)p6)->relY2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1a)) - ((GameObject*)obj)
                        ->anim.localPosY;
                    ((TrackP6Entry*)p6)->relZ2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x20)) - fz;
                    outA[0] = *(f32*)((char*)p4 + j * 0x4c + 0x4);
                    outA[1] = *(f32*)((char*)p4 + j * 0x4c + 0x8);
                    outA[2] = *(f32*)((char*)p4 + j * 0x4c + 0xc);
                    *(u8*)((char*)outA + 0x10) = *(u8*)((char*)p4 + j * 0x4c + 0x49);
                    p6 += 0x24;
                    total += 3;
                    outA = (f32*)((char*)outA + 0x14);
                    grp += 1;
                    outOff += 0x14;
                }
                j++;
            }
        }
        else
        {
            f32* m = *(f32**)((char*)d + 0xc);
            f32* p6start = (f32*)p6;
            int totalStart = total;
            f32* outA;

            lm[0] = m[0];
            lm[1] = m[4];
            lm[2] = m[8];
            lm[3] = m[12] - ((GameObject*)obj)->anim.localPosX;
            lm[4] = m[1];
            lm[5] = m[5];
            lm[6] = m[9];
            lm[7] = m[13] - ((GameObject*)obj)->anim.localPosY;
            lm[8] = m[2];
            lm[9] = m[6];
            lm[10] = m[10];
            lm[11] = m[14] - ((GameObject*)obj)->anim.localPosZ;
            j = (s16) * (s16*)((char*)d + 4);
            outA = (f32*)((char*)p5 + outOff);
            while (j < (s16) * (s16*)((char*)d + 0x1c) && grp < 0x4b0 && total < 0xe10)
            {
                if (p9 & (s8) * (u8*)((char*)p4 + j * 0x4c + 0x49))
                {
                    ((TrackP6Entry*)p6)->relX0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x10));
                    ((TrackP6Entry*)p6)->relY0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x16));
                    ((TrackP6Entry*)p6)->relZ0 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1c));
                    ((TrackP6Entry*)p6)->relX1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x12));
                    ((TrackP6Entry*)p6)->relY1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x18));
                    ((TrackP6Entry*)p6)->relZ1 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1e));
                    ((TrackP6Entry*)p6)->relX2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x14));
                    ((TrackP6Entry*)p6)->relY2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x1a));
                    ((TrackP6Entry*)p6)->relZ2 = __OSs16tof32((s16*)((char*)p4 + j * 0x4c + 0x20));
                    outA[0] = *(f32*)((char*)p4 + j * 0x4c + 0x4);
                    outA[1] = *(f32*)((char*)p4 + j * 0x4c + 0x8);
                    outA[2] = *(f32*)((char*)p4 + j * 0x4c + 0xc);
                    *(u8*)((char*)outA + 0x10) = *(u8*)((char*)p4 + j * 0x4c + 0x49);
                    p6 += 0x24;
                    total += 3;
                    outA = (f32*)((char*)outA + 0x14);
                    grp += 1;
                    outOff += 0x14;
                }
                j++;
            }
            if (totalStart < total)
            {
                PSMTXMultVecArray(lm, p6start, p6start, total - totalStart);
            }
        }
    }
    return grp;
}

extern const f32 lbl_803DECB8;
extern const f32 lbl_803DECBC;
extern const f32 lbl_803DECC0;
extern const f32 lbl_803DECC8;
extern f32 lbl_803DCF54;
extern f32 lbl_803DCF50;
extern f32 lbl_803DCF58;

int fn_800630D8(f32* p4, f32* p5, f32 cx, f32 cy, f32 r, s8 flag)
{
    f32 px;
    f32 dx, dy, sum, cc;
    f32 dx2, dy2;
    f32 B, nB, disc, root, denom;
    f32 t1, t2, t;
    f32 hitX, hitY, nx, ny, dot, proj;
    f32 vy4, vy5;
    f32 step8, step_x, step_y;
    f32 len2;

    if (__AR_Callback == r) return 0;

    px = p4[0];
    dx = px - cx;
    sum = dx * dx;
    dy = p5[0] - cy;
    {
        f32 dyy = dy * dy;
        sum = sum + dyy;
    }
    cc = sum - r * r;
    if (cc < __AR_Callback)
    {
        if (flag != 0)
        {
            p4[1] = px + lbl_803DCF54;
            p5[1] = p5[0] + lbl_803DCF50;
        }
        return 0;
    }

    dx2 = p4[1] - px;
    dy2 = p5[1] - p5[0];
    len2 = dx2 * dx2 + dy2 * dy2;
    if (len2 > __AR_Callback)
    {
        B = lbl_803DECB8 * (dx2 * dx + dy2 * dy);
        disc = B * B - lbl_803DECBC * len2 * cc;
        if (disc >= __AR_Callback)
        {
            root = sqrtf(disc);
            nB = -B;
            t1 = nB + root;
            denom = lbl_803DECB8 * len2;
            t1 = t1 / denom;
            t2 = (nB - root) / denom;
            if (t1 < __AR_Callback) t1 = lbl_803DECC0;
            if (t2 < __AR_Callback) t2 = lbl_803DECC0;
            if (t2 < t1) t1 = t2;
            t = t1;
            if (t >= __AR_Callback && t <= lbl_803DECC4)
            {
                lbl_803DCF58 = t;
                if (flag != 0)
                {
                    hitX = t * dx2 + p4[0];
                    hitY = t * dy2 + p5[0];
                    nx = (hitX - cx) / r;
                    ny = (hitY - cy) / r;
                    dot = -(hitX * nx + hitY * ny);
                    vy4 = p4[1];
                    vy5 = p5[1];
                    proj = dot + (nx * vy4 + ny * vy5);
                    p4[1] = vy4 - proj * nx;
                    p5[1] = vy5 - proj * ny;
                    step8 = lbl_803DECC8;
                    step_x = step8 * nx;
                    step_y = step8 * ny;
                    while (dot + (nx * p4[1] + ny * p5[1]) < step8)
                    {
                        p4[1] += step_x;
                        p5[1] += step_y;
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

extern f32 __PADFixBits;


#pragma optimization_level 2
void fn_80069B1C(u8* src1, u8* src2, u8* dst, f32 blend)
{
    u32 fmt;
    u32 w, h;
    int i, j;
    u32 wA, wB;
    int texA, texB;
    u8 redA, redB;
    int rf, gf, bf;

    if (src1 == NULL) return;
    if (src2 == NULL) return;
    if (dst == NULL) return;
    fmt = *(u8*)(src1 + 0x16);
    if (fmt != 4 && fmt != 6) return;
    if (*(u8*)(src2 + 0x16) != fmt) return;
    if (*(u8*)(dst + 0x16) != fmt) return;
    w = *(u16*)(src1 + 0xa);
    if (w != *(u16*)(src2 + 0xa)) return;
    h = *(u16*)(src1 + 0xc);
    if (h != *(u16*)(src2 + 0xc)) return;
    if (w != *(u16*)(dst + 0xa) || h != *(u16*)(dst + 0xc))
    {
        return;
    }
    {
        wA = (int)(__PADFixBits * blend) & 0xff;
        wB = (0xff - wA) & 0xff;
        if (fmt == 4)
        {
            for (i = 0; i < (int)*(u16*)(src1 + 0xc); i++)
            {
                int im, i5;
                j = 0;
                im = i & 0xfffffffc;
                i5 = (i & 3) * 8;
                for (; j < (int)*(u16*)(src1 + 0xa); j++)
                {
                    int i6 = (j & 3) * 2;
                    int i4 = (j >> 2) * 0x20;
                    int i12;
                    u8 *p;
                    p = src1 + i6; p += i4; p += i5;
                    i12 = (int)*(u16*)(src1 + 0xa) * im * 2;
                    p += i12;
                    texA = *(u16*)(p + 0x60);
                    redA = ((int)(texA & 0xf800) >> 8) | ((int)(texA & 0xe000) >> 13);
                    p = src2 + i6; p += i4; p += i5; p += i12;
                    texB = *(u16*)(p + 0x60);
                    redB = ((int)(texB & 0xf800) >> 8) | ((int)(texB & 0xe000) >> 13);
                    bf = ((u8)(((int)(wA * (u8)(((texA & 0x1f) << 3) | ((int)(texA & 0x1c) >> 2))) >> 8)
                        + ((int)(wB * (u8)(((texB & 0x1f) << 3) | ((int)(texB & 0x1c) >> 2))) >> 8)) & 0xf8) >> 3;
                    rf = ((u8)(((int)(redA * wA) >> 8) + ((int)(redB * wB) >> 8)) & 0xf8) << 8;
                    gf = ((u8)(((int)(wA * (u8)(((int)(texA & 0x7e0) >> 3) | ((int)(texA & 0x600) >> 9))) >> 8)
                        + ((int)(wB * (u8)(((int)(texB & 0x7e0) >> 3) | ((int)(texB & 0x600) >> 9))) >> 8)) & 0xfc) << 3;
                    p = dst + i6; p += i4; p += i5; p += i12;
                    *(u16*)(p + 0x60) = bf | (rf | gf);
                }
            }
        }
        else
        {
            for (i = 0; i < (int)*(u16*)(src1 + 0xc); i++)
            {
                int i5, i4;
                j = 0;
                i5 = (i >> 2) * 8;
                i4 = (i & 3) * 8;
                for (; j < (int)*(u16*)(src1 + 0xa); j++)
                {
                    int i9 = (j & 3) * 2;
                    int i12 = (j >> 2) * 0x40;
                    int i6;
                    u8 *ad, *bd, *cd;
                    u8 aLo, bLo, aHi, bHi;
                    ad = src1 + i9; ad += i12; ad += i4;
                    i6 = (int)*(u16*)(src1 + 0xa) * i5 * 2;
                    ad += i6;
                    bd = src2 + i9; bd += i12; bd += i4; bd += i6;
                    aLo = *(u16*)(ad + 0x60);
                    bLo = *(u16*)(bd + 0x60);
                    texA = *(u16*)(ad + 0x80);
                    aHi = (int)(texA & 0xff00) >> 8;
                    texB = *(u16*)(bd + 0x80);
                    bHi = (int)(texB & 0xff00) >> 8;
                    cd = dst + i9 + i12 + i4 + 0x60;
                    *(u16*)(cd + i6) = (u8)(((int)(aLo * wA) >> 8) + ((int)(bLo * wB) >> 8));
                    *(u16*)(cd + (int)*(u16*)(src1 + 0xa) * i5 * 2 + 0x20) =
                        ((u8)(((int)(aHi * wA) >> 8) + ((int)(bHi * wB) >> 8)) << 8)
                        | (u8)(((int)(wA * (u8)texA) >> 8) + ((int)(wB * (u8)texB) >> 8));
                }
            }
        }
        DCStoreRange(dst + 0x60, *(int*)(dst + 0x44));
    }
}
#pragma optimization_level reset

extern void Obj_BuildTransformMatrices(void* obj);
extern void fn_80296EB4(u8* p1, u8* p2);

void objHitDetectFn_80062e84(u8* obj, u8* newParent, int mode)
{
    u8* oldParent;
    u8* hitReact;
    int yawSum;
    f32 dirX;
    f32 dirZ;
    u8 dirBuf[16];

    oldParent = *(u8**)&((GameObject*)obj)->anim.parent;
    if (oldParent == newParent) return;

    if (oldParent != NULL) Obj_BuildTransformMatrices(oldParent);
    if (newParent != NULL) Obj_BuildTransformMatrices(newParent);

    if (((GameObject*)obj)->anim.classId == 1)
    {
        fn_80296EB4(obj, newParent);
        return;
    }

    *(u8**)(obj + 0x30) = newParent;
    hitReact = *(u8**)&((GameObject*)obj)->anim.hitReactState;
    if (oldParent != NULL)
    {
        Obj_TransformLocalPointToWorld(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                       &((GameObject*)obj)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosY, &((GameObject*)obj)->anim.worldPosZ, (u32)oldParent);
        Obj_TransformLocalPointToWorld(*(f32*)(obj + 0x80), *(f32*)(obj + 0x84), *(f32*)(obj + 0x88),
                                       (f32*)(obj + 0x8c), (f32*)(obj + 0x90), (f32*)(obj + 0x94), (u32)oldParent);
        Obj_TransformLocalVectorToWorld(((GameObject*)obj)->anim.velocityX, __AR_Callback, ((GameObject*)obj)->anim.velocityZ,
                                        &dirX, (f32*)dirBuf, &dirZ, (u32)oldParent);
        yawSum = *(s16*)oldParent + ((GameObject*)obj)->anim.rotX;
    }
    else
    {
        dirX = ((GameObject*)obj)->anim.velocityX;
        dirZ = ((GameObject*)obj)->anim.velocityZ;
        yawSum = ((GameObject*)obj)->anim.rotX;
    }

    if (mode != 0)
    {
        if (*(u8**)(obj + 0x30) != NULL)
        {
            Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ,
                                           &((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.localPosY, &((GameObject*)obj)->anim.localPosZ,
                                           (u32)*(u8**)(obj + 0x30));
            Obj_TransformWorldPointToLocal(*(f32*)(obj + 0x8c), *(f32*)(obj + 0x90), *(f32*)(obj + 0x94),
                                           (f32*)(obj + 0x80), (f32*)(obj + 0x84), (f32*)(obj + 0x88),
                                           (u32)*(u8**)(obj + 0x30));
            Obj_TransformWorldVectorToLocal(dirX, __AR_Callback, dirZ,
                                            (f32*)(obj + 0x24), (f32*)dirBuf, (f32*)(obj + 0x2c),
                                            (u32)*(u8**)(obj + 0x30));
            yawSum = yawSum - *(s16*)(*(u8**)(obj + 0x30));
            if (yawSum > 0x8000) yawSum -= 0xffff;
            if (yawSum < -0x8000) yawSum += 0xffff;
            ((GameObject*)obj)->anim.rotX = yawSum;
        }
        else
        {
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.worldPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.worldPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.worldPosZ;
            ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.previousWorldPosX;
            ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.previousWorldPosY;
            ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.previousWorldPosZ;
            ((GameObject*)obj)->anim.velocityX = dirX;
            ((GameObject*)obj)->anim.velocityZ = dirZ;
            ((GameObject*)obj)->anim.rotX = yawSum;
        }
    }

    if (hitReact != NULL)
    {
        *(f32*)(hitReact + 0x10) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(hitReact + 0x14) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(hitReact + 0x18) = ((GameObject*)obj)->anim.localPosZ;
        *(f32*)(hitReact + 0x1c) = ((GameObject*)obj)->anim.worldPosX;
        *(f32*)(hitReact + 0x20) = ((GameObject*)obj)->anim.worldPosY;
        *(f32*)(hitReact + 0x24) = ((GameObject*)obj)->anim.worldPosZ;
    }
}

extern u8 gIntersectSegmentTypeTable[];
extern int lbl_803DCF64;
extern int lbl_803DCF68;
extern s8 lbl_803DCF60;
extern const f32 lbl_803DECE8;
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);


int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f)
{
    u8* base = gIntersectSegmentTypeTable;
    TrackBlockDescriptor* desc = (TrackBlockDescriptor*)(base + 0x424);
    TrackBlockDescriptor* end;
    u8* ptr;
    int i, j;
    int sorted;
    int conv[6];
    f32 tx, ty, tz;

    if (e >= 0)
    {
        conv[0] = b;
        conv[3] = b;
        conv[1] = (int)(c - lbl_803DECE8);
        conv[4] = (int)(lbl_803DECE8 + c);
        conv[2] = d;
        conv[5] = d;
        hitDetectFn_800691c0((int*)a, conv, f, 1);
    }
    else
    {
        if (e == -1) e = 0;
        else e = 1;
    }

    lbl_803DCF68 = (int)(base + 0xdc);
    lbl_803DCF64 = (int)(base + 0x50);
    lbl_803DCF60 = 0;
    end = (TrackBlockDescriptor*)(base + 0x424) + gActiveTrackBlockCount;
    for (; desc < end; desc++)
    {
        if (lbl_803DCF60 >= 0x23) break;
        if (desc->object != NULL)
        {
            Matrix_TransformPoint(desc->currentMatrix, b, __AR_Callback, d, &tx, &ty, &tz);
            fn_800659A8((void*)(gTrackTriangleBuffer + desc->firstTriangle * 0x4c),
                        (void*)(gTrackTriangleBuffer + desc[1].firstTriangle * 0x4c),
                        desc, tx, tz, e);
        }
        else
        {
            fn_800659A8((void*)(gTrackTriangleBuffer + desc->firstTriangle * 0x4c),
                        (void*)(gTrackTriangleBuffer + desc[1].firstTriangle * 0x4c),
                        desc, b, d, e);
        }
    }

    ptr = base + 0xdc;
    i = 0;
    for (j = 0; j < lbl_803DCF60; j++)
    {
        *(u8**)(lbl_803DCF64 + i) = ptr;
        ptr += 0x18;
        i += 4;
    }

    sorted = 0;
    while (!sorted)
    {
        sorted = 1;
        i = 0;
        for (j = 0; j < lbl_803DCF60 - 1; j++)
        {
            f32** pp = (f32**)(lbl_803DCF64 + i);
            f32* p5 = pp[0];
            if (*p5 < *pp[1])
            {
                sorted = 0;
                pp[0] = pp[1];
                *(f32**)(lbl_803DCF64 + i + 4) = p5;
            }
            i += 4;
        }
    }

    *(u8**)out = base + 0x50;
    return lbl_803DCF60;
}

extern void Matrix_TransformVector(void* mtx, f32* in, f32* out);
extern f32 lbl_803DECE0[2];

void fn_800659A8(void* p3, void* p4, void* desc, f32 a, f32 b, int e)
{
    u8* v;
    f32 ox;
    f32 planeC;
    f32 oz;
    f32 arrA[7];
    f32 arrB[7];
    f32 arrC[7];
    f32 vec[3];

    if (*(void**)desc == NULL)
    {
        a -= (f32)((int*)gTrackGridOrigin)[0];
        b -= (f32)((int*)gTrackGridOrigin)[2];
    }
    for (v = p3; v < p4; v += 0x4c)
    {
        s8 fl = *(s8*)(v + 0x49);
        int i;
        int inside;

        if (fl & 0x10)
        {
            if (!(fl & 0x4)) continue;
        }
        vec[0] = *(f32*)(v + 0x4);
        vec[1] = *(f32*)(v + 0x8);
        vec[2] = *(f32*)(v + 0xc);
        if (!(vec[1] > __AR_Callback))
        {
            if (e == 0) continue;
            if (__AR_Callback == vec[1]) continue;
        }
        planeC = -(vec[0] * a + vec[2] * b + *(f32*)v) / vec[1];
        arrA[0] = (f32)(s16) * (s16*)(v + 0x10);
        arrB[0] = (f32)(s16) * (s16*)(v + 0x16);
        arrC[0] = (f32)(s16) * (s16*)(v + 0x1c);
        arrA[1] = (f32)(s16) * (s16*)(v + 0x12);
        arrB[1] = (f32)(s16) * (s16*)(v + 0x18);
        arrC[1] = (f32)(s16) * (s16*)(v + 0x1e);
        arrA[2] = (f32)(s16) * (s16*)(v + 0x14);
        arrB[2] = (f32)(s16) * (s16*)(v + 0x1a);
        arrC[2] = (f32)(s16) * (s16*)(v + 0x20);
        inside = 1;
        {
            f32 c30 = lbl_803DECC0;
            f32 c31 = __AR_Callback;
            f32 c24 = lbl_803DECE0[1];
            for (i = 0; i < 3; i++)
            {
                int nxt = i + 1;
                f32 nx, ny, nz, mag;

                if (nxt > 2) nxt = 0;
                arrA[3] = c30 * vec[0] + arrA[i];
                arrB[3] = c30 * vec[1] + arrB[i];
                arrC[3] = c30 * vec[2] + arrC[i];
                nx = arrB[3] * (arrC[i] - arrC[nxt]) + (arrB[i] * (arrC[nxt] - arrC[3]) + arrB[nxt] * (arrC[3] - arrC[
                    i]));
                ny = arrC[3] * (arrA[i] - arrA[nxt]) + (arrC[i] * (arrA[nxt] - arrA[3]) + arrC[nxt] * (arrA[3] - arrA[
                    i]));
                nz = arrA[3] * (arrB[i] - arrB[nxt]) + (arrA[i] * (arrB[nxt] - arrB[3]) + arrA[nxt] * (arrB[3] - arrB[
                    i]));
                mag = sqrtf(nx * nx + ny * ny + nz * nz);
                if (mag > c31)
                {
                    f32 s = lbl_803DECC4 / mag;
                    nx *= s;
                    ny *= s;
                    nz *= s;
                }
                if (-(nx * arrA[i] + ny * arrB[i] + nz * arrC[i]) +
                    (nx * a + ny * planeC + nz * b) > c24)
                {
                    inside = 0;
                    break;
                }
            }
        }
        if (inside == 0) continue;
        if ((s8)lbl_803DCF60 >= 0x23) break;
        if (*(void**)desc != NULL)
        {
            Matrix_TransformPoint(*(void**)((char*)desc + 0xc), a, planeC, b, &ox, &planeC, &oz);
            Matrix_TransformVector(*(void**)((char*)desc + 0xc), vec, vec);
        }
        *(f32*)(lbl_803DCF68 + 0) = planeC;
        *(u8*)(lbl_803DCF68 + 0x14) = *(u8*)(v + 0x48);
        *(f32*)(lbl_803DCF68 + 0x4) = vec[0];
        *(f32*)(lbl_803DCF68 + 0x8) = vec[1];
        *(f32*)(lbl_803DCF68 + 0xc) = vec[2];
        *(int*)(lbl_803DCF68 + 0x10) = *(int*)desc;
        lbl_803DCF68 = lbl_803DCF68 + 0x18;
        lbl_803DCF60++;
    }
}

extern f32 fn_802925C4(f32 x, f32 y);
extern float fn_802943F4(float x);
extern float floor(float x);
extern const f32 lbl_803DECEC;

int fn_800660C8(f32* a, f32* b, f32* c, f32* p, int type, f32 f1p, f32 y)
{
    f32 d0[3];
    f32 d1[3];

    if ((u8)type == 3)
    {
        f32 fa, fb, scale;
        b[0] = c[0];
        b[1] = c[1];
        b[2] = c[2];
        d0[0] = b[0] - a[0];
        d0[1] = b[1] - a[1];
        d0[2] = b[2] - a[2];
        Vec3_Normalize(d0);
        {
            f32 fbd = b[1] * p[1];
            f32 fad = a[1] * p[1];
            fb = (fbd + b[0] * p[0] + b[2] * p[2] + p[3]) - y;
            fa = (fad + a[0] * p[0] + a[2] * p[2] + p[3]) - y;
        }
        if (fa != fb)
            scale = fa / (fa - fb);
        else
            scale = __AR_Callback;
        d0[0] = b[0] - a[0];
        d0[1] = b[1] - a[1];
        d0[2] = b[2] - a[2];
        b[0] = d0[0] * scale;
        b[1] = d0[1] * scale;
        b[2] = d0[2] * scale;
        b[0] = b[0] + a[0];
        b[1] = b[1] + a[1];
        b[2] = b[2] + a[2];
        return 1;
    }
    if (p[1] < __AR_Size && p[1] > lbl_803DECEC)
    {
        switch ((u8)type)
        {
        case 1:
        case 8:
        case 0xa:
            {
                f32 dotL = b[1] * p[1];
                f32 dot = dotL + b[0] * p[0] + b[2] * p[2] + p[3];
                y = y - dot;
                if (y > __AR_Callback)
                {
                    f32 px = p[0] * p[0];
                    f32 pz = p[2] * p[2];
                    f32 d = fn_802943F4(fn_802925C4(p[1], sqrtf(px + pz)));
                    if (__AR_Callback != d)
                        y = y / d;
                    d1[0] = p[0];
                    d1[1] = __AR_Callback;
                    d1[2] = p[2];
                    Vec3_Normalize(d1);
                    b[0] = y * d1[0] + b[0];
                    b[2] = y * d1[2] + b[2];
                }
                break;
            }
        default:
            {
                f32 dot, t, dotL;
                b[0] = b[0] - f1p * p[0];
                b[1] = b[1] - f1p * p[1];
                b[2] = b[2] - f1p * p[2];
                dotL = b[1] * p[1];
                dot = dotL + b[0] * p[0] + b[2] * p[2] + p[3];
                t = y - dot;
                b[0] = t * p[0] + b[0];
                b[1] = t * p[1] + b[1];
                b[2] = t * p[2] + b[2];
                break;
            }
        }
    }
    else
    {
        switch ((u8)type)
        {
        case 5:
        case 8:
            {
                f32 dot, t, dotL;
                b[0] = b[0] - f1p * p[0];
                b[1] = b[1] - f1p * p[1];
                b[2] = b[2] - f1p * p[2];
                dotL = b[1] * p[1];
                dot = dotL + b[0] * p[0] + b[2] * p[2] + p[3];
                t = y - dot;
                b[0] = t * p[0] + b[0];
                b[1] = t * p[1] + b[1];
                b[2] = t * p[2] + b[2];
                break;
            }
        case 0xb:
        default:
            {
                f32 dotL = b[1] * p[1];
                f32 dot = dotL + b[0] * p[0] + b[2] * p[2] + p[3];
                y = y - dot;
                if (y > __AR_Callback)
                {
                    f32 px = p[0] * p[0];
                    f32 pz = p[2] * p[2];
                    f32 d = floor(fn_802925C4(p[1], sqrtf(px + pz)));
                    b[1] = b[1] + y / d;
                }
                break;
            }
        }
    }
    return 1;
}

int hitDetectFn_800664fc(void* tri, f32* rayOrig, f32* rayDir, f32 maxd, f32 maxStep, f32 epsArg, f32* out29,
                         f32* outNrm, f32* outDist)
{
    f32 nrm[3];
    f32 e[3];
    f32 tmp14[3];
    f32 hit[3];
    f32 len, f29, f12;
    f32* T = tri;

    Vec3_Cross(rayDir, T + 6, nrm);
    len = Vec3_Normalize(nrm);
    if (__AR_Callback == len) return 0;
    e[0] = rayOrig[0] - T[0];
    e[1] = rayOrig[1] - T[1];
    e[2] = rayOrig[2] - T[2];
    {
        f32 d0 = nrm[1] * e[1];
        f29 = d0 + nrm[0] * e[0] + nrm[2] * e[2];
    }
    f29 = f29 * f29;
    if (f29 <= T[10])
    {
        Vec3_Cross(e, T + 6, tmp14);
        {
            f32 dl = tmp14[1] * nrm[1];
            len = -(dl + tmp14[0] * nrm[0] + tmp14[2] * nrm[2]) / len;
        }
        Vec3_Cross(nrm, T + 6, tmp14);
        Vec3_Normalize(tmp14);
        {
            f32 s = sqrtf(T[10] - f29);
            f32 dd = rayDir[1] * tmp14[1];
            f32 dn = dd + rayDir[0] * tmp14[0] + rayDir[2] * tmp14[2];
            f32 r = s / dn;
            if (r < *(f32*)&__AR_Callback) r = -r;
            len = len - r;
        }
        if (len >= __AR_Callback)
        {
            if (len <= maxd)
            {
                hit[0] = rayDir[0] * len;
                hit[1] = rayDir[1] * len;
                hit[2] = rayDir[2] * len;
                hit[0] = rayOrig[0] + hit[0];
                hit[1] = rayOrig[1] + hit[1];
                hit[2] = rayOrig[2] + hit[2];
                {
                    f32 d1 = hit[1] * T[7];
                    f32 d2 = T[7] * T[1];
                    f12 = (d1 + hit[0] * T[6] + hit[2] * T[8]) -
                        (d2 + T[6] * T[0] + T[8] * T[2]);
                }
                if (f12 >= __AR_Callback)
                {
                    if (f12 <= T[11])
                    {
                        tmp14[0] = T[6] * f12;
                        tmp14[1] = T[7] * f12;
                        tmp14[2] = T[8] * f12;
                        tmp14[0] = T[0] + tmp14[0];
                        tmp14[1] = T[1] + tmp14[1];
                        tmp14[2] = T[2] + tmp14[2];
                        outNrm[0] = hit[0] - tmp14[0];
                        outNrm[1] = hit[1] - tmp14[1];
                        outNrm[2] = hit[2] - tmp14[2];
                        Vec3_Normalize(outNrm);
                        {
                            f32 dh = *(f32*)((u8*)hit + 4) * outNrm[1];
                            outNrm[3] = T[9] - (dh + *(f32*)((u8*)hit + 0) * outNrm[0] + *(f32*)((u8*)hit + 8) * outNrm[2]);
                        }
                        out29[0] = *(f32*)((u8*)hit + 0);
                        out29[1] = *(f32*)((u8*)hit + 4);
                        out29[2] = *(f32*)((u8*)hit + 8);
                        *outDist = len;
                        return 3;
                    }
                }
            }
        }
    }
    return 0;
}

extern u8 hitDetect_800667ec(int mode, void* tri1, void* tri2, int startPos, int endPos, int count, void* slots, int flagsArg);
extern void Obj_TransformLocalVectorByWorldMatrix(int v, f32* a, f32* b);

#pragma ppc_unroll_speculative on
#pragma ppc_unroll_factor_limit 8
#pragma ppc_unroll_instructions_limit 160
u8 hitDetectFn_80067958(void* contactSrc, int param_2, int param_3, int count, void* results)
{
    f32 initB, initA;
    void** pp;
    f32* fp;
    s16 i;
    u8 hitCount;
    u8* tbl = (u8*)gTrackBlockDescriptors;

    if (count > 4) count = 4;
    *(u16*)((u8*)results + 0x6c) = 0;

    initA = __AR_Callback;
    initB = lbl_803DECC4;
    fp = results;
    pp = results;
    for (i = 0; i < count; i++)
    {
        fp[i * 4 + 0] = initA;
        fp[i * 4 + 1] = initB;
        fp[i * 4 + 2] = initA;
        fp[i * 4 + 3] = initA;
        pp[i + 0x17] = NULL;
    }

    {
        extern int hitDetect_800667ec();
        hitCount = hitDetect_800667ec(0,
                               (void*)(gTrackTriangleBuffer + *(s16*)(tbl + 4) * 0x4c),
                               (void*)(gTrackTriangleBuffer + *(s16*)(tbl + 0x1c) * 0x4c),
                               param_2, param_3, count, results, 0);
    }

    fp = results;
    pp = results;
    for (i = 0; i < count; i++)
    {
        if (pp[i + 0x17] != NULL)
        {
            Obj_TransformLocalVectorByWorldMatrix((int)pp[i + 0x17], &fp[i * 4], &fp[i * 4]);
            if (contactSrc != NULL)
            {
                ObjHits_AddContactObject((int)pp[i + 0x17], (int)contactSrc);
            }
        }
    }

    *(u8*)((u8*)results + 0x6e) = hitCount;
    return hitCount;
}
#pragma ppc_unroll_speculative off

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} GolfWGPipe;

extern volatile GolfWGPipe GXWGFifo : (0xCC008000);

static inline void GXPosition3s16(const s16 x, const s16 y, const s16 z)
{
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = z;
}

static inline void GXTexCoord2s16(const s16 x, const s16 y)
{
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
}

extern void Obj_BuildWorldTransformMatrix(int obj, f32* out, int flag);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXSetTexCoordGen2(int a, int b, int c, int d, int e, int f);
extern void GXSetTevKColor(int id, void* color);
extern void GXSetTevKAlphaSel(int stage, int sel);
extern void GXSetNumTevStages(u8 nStages);
extern void GXSetNumIndStages(u8 nIndStages);
extern void GXSetChanCtrl(int a, int b, int c, int d, int e, int f, int g);
extern void GXSetNumChans(u8 nChans);
extern void GXSetTevOrder(int a, int b, int c, int d);
extern void GXSetTevDirect(int stage);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevColorOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetTevAlphaOp(int stage, int a, int b, int c, int d, int e);
extern void GXSetCullMode(int mode);
extern void GXSetCurrentMtx(u32 id);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void selectTexture(int tex, int slot);
extern void GXBegin(int type, int fmt, int count);

#pragma peephole on
void objDrawFn_80061654(int obj, int placementObj)
{
    s16* shadowVerts;
    u8 alpha;
    void* viewMtx;
    int kColor;
    int kColorCopy;
    f32 mtx[16];
    f32 outMtx[16];

    shadowVerts = *(s16**)(placementObj + 0x54);
    if (*(u8*)((u8*)shadowVerts + 0x18) == 0)
    {
        fn_8006135C(shadowVerts, (void*)obj);
    }
    if (*(u8*)((u8*)shadowVerts + 0x18) != 0xff)
    {
        alpha = objShadowFn_80062378((void*)obj, 0x96);
        *((u8*)&kColor + 3) = alpha;
        if (alpha != 0)
        {
            viewMtx = Camera_GetViewMatrix();
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            mtx[0] = lbl_803DEC68;
            mtx[1] = lbl_803DEC58;
            mtx[2] = lbl_803DEC58;
            mtx[4] = lbl_803DEC58;
            mtx[5] = lbl_803DEC68;
            mtx[6] = lbl_803DEC58;
            mtx[8] = lbl_803DEC58;
            mtx[9] = lbl_803DEC58;
            mtx[10] = lbl_803DEC68;
            PSMTXConcat(viewMtx, mtx, outMtx);
            GXLoadPosMtxImm(outMtx, 0x1b);
            GXClearVtxDesc();
            GXSetVtxDesc(9, 1);
            GXSetVtxDesc(0xd, 1);
            GXSetNumTexGens(1);
            GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
            kColorCopy = kColor;
            GXSetTevKColor(0, &kColorCopy);
            GXSetTevKAlphaSel(0, 0x1c);
            GXSetNumTevStages(1);
            GXSetNumIndStages(0);
            GXSetChanCtrl(GX_COLOR0A0, GX_DISABLE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_DISABLE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
            GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
            GXSetTevDirect(GX_TEVSTAGE0);
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
            GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_KONST, GX_CA_TEXA, GX_CA_ZERO);
            GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_ENABLE, GX_TEVPREV);
            GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_ENABLE, GX_TEVPREV);
            gxSetZMode_(1, 3, 0);
            GXSetCullMode(GX_CULL_NONE);
            GXSetCurrentMtx(0x1b);
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
            selectTexture((int)((ObjAnimComponent*)obj)->modelState->shadowTexture, 0);
            GXBegin(0x80, 6, 4);
            GXPosition3s16(shadowVerts[0], shadowVerts[1], shadowVerts[2]);
            GXTexCoord2s16(0, 0);
            GXPosition3s16(shadowVerts[3], shadowVerts[4], shadowVerts[5]);
            GXTexCoord2s16(0x400, 0);
            GXPosition3s16(shadowVerts[6], shadowVerts[7], shadowVerts[8]);
            GXTexCoord2s16(0x400, 0x400);
            GXPosition3s16(shadowVerts[9], shadowVerts[10], shadowVerts[11]);
            GXTexCoord2s16(0, 0x400);
            GXSetCurrentMtx(0);
        }
    }
}
#pragma peephole reset

void trackDolphin_buildShadowVolumePlanes(int* obj, void* buf48, void* bufA8)
{
    f32* verts = buf48;
    f32* planes = bufA8;
    f32 e1x, e2x, e1y, e2y, e1z, e2z;
    f32 nrm[3];

    e1x = verts[6] - verts[9];
    e1y = verts[7] - verts[10];
    e1z = verts[8] - verts[0xb];
    e2x = verts[0x15] - verts[9];
    e2y = verts[0x16] - verts[10];
    e2z = verts[0x17] - verts[0xb];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[0] = -nrm[0];
    planes[1] = -nrm[1];
    planes[2] = -nrm[2];
    planes[3] = -(planes[2] * verts[0xb] + planes[0] * verts[9] + planes[1] * verts[10]);

    e1x = verts[0x12] - verts[0xf];
    e1y = verts[0x13] - verts[0x10];
    e1z = verts[0x14] - verts[0x11];
    e2x = verts[3] - verts[0xf];
    e2y = verts[4] - verts[0x10];
    e2z = verts[5] - verts[0x11];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[5] = -nrm[0];
    planes[6] = -nrm[1];
    planes[7] = -nrm[2];
    planes[8] = -(planes[7] * verts[0x11] + planes[5] * verts[0xf] + planes[6] * verts[0x10]);

    e1x = verts[0xf] - verts[0xc];
    e1y = verts[0x10] - verts[0xd];
    e1z = verts[0x11] - verts[0xe];
    e2x = verts[0] - verts[0xc];
    e2y = verts[1] - verts[0xd];
    e2z = verts[2] - verts[0xe];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[10] = -nrm[0];
    planes[0xb] = -nrm[1];
    planes[0xc] = -nrm[2];
    planes[0xd] = -(planes[0xc] * verts[0xe] + planes[10] * verts[0xc] + planes[0xb] * verts[0xd]);

    e1x = verts[9] - verts[0];
    e1y = verts[10] - verts[1];
    e1z = verts[0xb] - verts[2];
    e2x = verts[0xc] - verts[0];
    e2y = verts[0xd] - verts[1];
    e2z = verts[0xe] - verts[2];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[0xf] = -nrm[0];
    planes[0x10] = -nrm[1];
    planes[0x11] = -nrm[2];
    planes[0x12] = -(planes[0x11] * verts[2] + planes[0xf] * verts[0] + planes[0x10] * verts[1]);

    e1x = verts[0x12] - verts[0x15];
    e1y = verts[0x13] - verts[0x16];
    e1z = verts[0x14] - verts[0x17];
    e2x = verts[0xc] - verts[0x15];
    e2y = verts[0xd] - verts[0x16];
    e2z = verts[0xe] - verts[0x17];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[0x14] = -nrm[0];
    planes[0x15] = -nrm[1];
    planes[0x16] = -nrm[2];
    planes[0x17] = -(planes[0x16] * verts[0x17] + planes[0x14] * verts[0x15] + planes[0x15] * verts[0x16]);

    e1x = verts[3] - verts[0];
    e1y = verts[4] - verts[1];
    e1z = verts[5] - verts[2];
    e2x = verts[9] - verts[0];
    e2y = verts[10] - verts[1];
    e2z = verts[0xb] - verts[2];
    nrm[0] = e2y * e1z - e2z * e1y;
    nrm[1] = -(e2x * e1z - e2z * e1x);
    nrm[2] = e2x * e1y - e2y * e1x;
    PSVECNormalize(nrm, nrm);
    planes[0x19] = -nrm[0];
    planes[0x1a] = -nrm[1];
    planes[0x1b] = -nrm[2];
    planes[0x1c] = -(planes[0x1b] * verts[2] + planes[0x19] * verts[0] + planes[0x1a] * verts[1]);
}

extern void objectShadow_setupSwappedProjectedTexture(int hdr, void* col, void* mtx);
extern void objectShadow_setupProjectedTexture(int hdr, void* col, void* mtx);
extern void fn_80077AD8(int hdr, void* col, void* mtx, f32 f);
extern void fn_80077EF8(int hdr, void* col, void* mtx, f32 f);
extern const f32 lbl_803DEC78;
extern const f32 lbl_803DEC80;

#pragma ppc_unroll_speculative off
#pragma opt_strength_reduction off
void objDrawFn_80061f0c(void* cache, void* blockData, int* obj, int slot, void* p7, void* buf48, f32 f)
{
    u8 col[4];
    u8 save_18[12];
    u8 save_c[12];
    f32 mtx[16];
    f32 outMtx[16];
    f32 f31, f30;
    f32 kf;
    s16 s31, s30, s29;
    u32 handle;
    int hdr;
    void* viewMtx;

    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    col[0] = 0;
    col[1] = 0;
    col[2] = 0;
    col[3] = *(u8*)(((MapBlockData*)blockData)->unkC + 0x64);
    f31 = ((GameObject*)obj)->anim.rootMotionScale;
    s31 = ((GameObject*)obj)->anim.rotX;
    s30 = ((GameObject*)obj)->anim.rotZ;
    s29 = ((GameObject*)obj)->anim.rotY;
    handle = *(u32*)&((MapBlockData*)blockData)->allocHandle;
    if (handle == 0 || handle != 0xFFFFFFFF)
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803DEC78;
    else
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803DEC68;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rotY = 0;
    if ((*(u32*)&((MapBlockData*)blockData)->flags & 0x2000) == 0)
        ((GameObject*)obj)->anim.rotZ = 0;
    if (*(u32*)&((MapBlockData*)blockData)->flags & 0x20)
    {
        memcpy(save_c, (char*)obj + 0xc, 0xc);
        memcpy(save_18, (char*)obj + 0x18, 0xc);
        memcpy((char*)((int)obj + 0x18), (char*)blockData + 0x20, 0xc);
        memcpy((char*)((int)obj + 0xc), (char*)((int)blockData + 0x20), 0xc);
    }
    Obj_BuildWorldTransformMatrix((int)obj, mtx, 0);
    viewMtx = Camera_GetViewMatrix();
    PSMTXConcat(viewMtx, mtx, outMtx);
    GXLoadPosMtxImm(outMtx, 0);
    if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & 0x4)
    {
        int c = *(int*)col;
        objectShadow_setupSwappedProjectedTexture(((MapBlockData*)blockData)->unkC, &c, mtx);
    }
    else
    {
        if (obj == Obj_GetPlayerObject())
            f30 = 10.0f;
        else
            f30 = ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale;
        handle = *(u32*)&((MapBlockData*)blockData)->allocHandle;
        if (handle == 0xFFFFFFFF)
        {
            u32 h2 = textureFn_8006c5c4();
            hdr = ((MapBlockData*)blockData)->unkC;
            if (*(u32*)(hdr + 0x60) != h2)
                goto drawSpecial;
        }
        {
            int c = *(int*)col;
            objectShadow_setupProjectedTexture(((MapBlockData*)blockData)->unkC, &c, mtx);
        }
        goto afterDraw;
    drawSpecial:
        if (*(u8*)(hdr + 0x65) == 0xff)
        {
            int c = *(int*)col;
            fn_80077AD8(((MapBlockData*)blockData)->unkC, &c, mtx, f30);
        }
        else
        {
            int c = *(int*)col;
            fn_80077EF8(((MapBlockData*)blockData)->unkC, &c, mtx, f30);
        }
    afterDraw:;
    }
    GXSetCullMode(GX_CULL_FRONT);
    GXSetCurrentMtx(0);
    ((GameObject*)obj)->anim.rootMotionScale = f31;
    ((GameObject*)obj)->anim.rotX = s31;
    ((GameObject*)obj)->anim.rotY = s29;
    ((GameObject*)obj)->anim.rotZ = s30;
    if (*(u32*)&((MapBlockData*)blockData)->allocHandle == 0)
    {
        f32* cv;
        int off;
        int i;
        int* vbuf;
        ((MapBlockData*)blockData)->allocHandle = (int)mmAlloc(slot * 0x12 + 8, 0x18, 0);
        vbuf = *(int**)&((MapBlockData*)blockData)->allocHandle;
        if (vbuf == NULL) return;
        vbuf[0] = (int)vbuf + 8;
        *(int*)(((MapBlockData*)blockData)->allocHandle + 4) = slot * 3;
        i = 0;
        cv = cache;
        off = 0;
        kf = lbl_803DEC80;
        for (; i < *(u32*)(((MapBlockData*)blockData)->allocHandle + 4); off += 6)
        {
            *(s16*)(*(int*)(((MapBlockData*)blockData)->allocHandle) + off + 0) = kf * cv[0];
            *(s16*)(*(int*)(((MapBlockData*)blockData)->allocHandle) + off + 2) = kf * cv[1];
            *(s16*)(*(int*)(((MapBlockData*)blockData)->allocHandle) + off + 4) = kf * cv[2];
            cv += 3;
            i++;
        }
    }
    handle = *(u32*)&((MapBlockData*)blockData)->allocHandle;
    if (handle != 0xFFFFFFFF)
    {
        int k;
        int off;
        GXBegin(0x90, 0, *(int*)(((MapBlockData*)blockData)->allocHandle + 4) & 0xffff);
        k = 0;
        off = k;
        for (; k < *(u32*)(((MapBlockData*)blockData)->allocHandle + 4); off += 6)
        {
            s16* ep = (s16*)(*(int*)(((MapBlockData*)blockData)->allocHandle) + off);
            s16 e2 = ep[2];
            s16 e1 = ep[1];
            s16 e0 = ep[0];
            GXWGFifo.s16 = e0;
            GXWGFifo.s16 = e1;
            GXWGFifo.s16 = e2;
            k++;
        }
    }
    else
    {
        int i;
        int vi;
        int off;
        GXBegin(0x90, 2, (slot * 3) & 0xffff);
        vi = 0;
        off = vi;
        for (i = 0; i < slot; i++)
        {
            f32* v0 = (f32*)((char*)cache + off);
            f32 a0 = v0[0];
            f32 a1 = v0[1];
            f32 a2 = v0[2];
            GXWGFifo.f32 = a0;
            GXWGFifo.f32 = a1;
            GXWGFifo.f32 = a2;
            {
                f32* v1 = (f32*)((char*)cache + (vi + 1) * 0xc);
                f32 b2 = v1[2];
                f32 b1 = v1[1];
                f32 b0 = v1[0];
                GXWGFifo.f32 = b0;
                GXWGFifo.f32 = b1;
                GXWGFifo.f32 = b2;
            }
            {
                f32* v2 = (f32*)((char*)cache + (vi + 2) * 0xc);
                f32 c2 = v2[2];
                f32 c1 = v2[1];
                f32 c0 = v2[0];
                GXWGFifo.f32 = c0;
                GXWGFifo.f32 = c1;
                GXWGFifo.f32 = c2;
            }
            vi += 3;
            off += 0x24;
        }
    }
    if (*(u32*)&((MapBlockData*)blockData)->flags & 0x20)
    {
        memcpy((char*)((int)obj + 0xc), save_c, 0xc);
        memcpy((char*)((int)obj + 0x18), save_18, 0xc);
    }
}
#pragma opt_strength_reduction reset
#pragma ppc_unroll_speculative on

typedef struct
{
    u8 r, g, b, a;
} GlowGXColor;

extern void Camera_RebuildProjectionMatrix(void);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_80079804(void);
extern void gxTextureFn_800794e0(void);
extern void GXSetFog(int type, GlowGXColor col, f32 a, f32 b, f32 c, f32 d);
extern void gxBlendFn_800789ac(void);
extern u8 skyFn_8008919c(int);
extern void skyBuildSunModelMatrix(f32 * out);
extern void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ);
extern void Camera_NdcToScreen(f32 x, f32 y, f32 z, int* ox, int* oy, int* oz);
extern int depthReadRequestPoll(int x, int y, void* p);
extern u8 pauseMenuGetState(void);
extern void* fn_8008912C(void);
extern void _gxSetTevColor2(int r, int g, int b, int a);
extern int sSynthFadeUnit;
extern int renderFlags;
extern u8 colorScale;
extern f32 gSunFlareFade;
extern int gSunOcclusionSampleOffsets[];
extern f32 lbl_803DEBD4, lbl_803DEBD8, lbl_803DEBDC;
extern f32 displayOffsetH_803DEBFC, flushFlag_803DEBE4;
extern f32 Initialized_803DEC30, EnabledBits_803DEC34, ResettingBits_803DEC38;
extern f32 RecalibrateBits_803DEC3C, WaitingBits_803DEC40;

void renderGlows(void)
{
    GlowGXColor fogCol;
    int sx, sy, sz;
    f32 px, py, pz;
    f32 sunMtx[12];
    f32 dir[3];
    f32 cam[3];
    int alpha = 0xff;
    u8 sky;
    f32 sunDot;

    fogCol = *(GlowGXColor*)&sSynthFadeUnit;
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    textureSetupFn_800799c0();
    gxTextureFn_800794e0();
    textRenderSetupFn_80079804();
    GXSetFog(0, fogCol, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC);
    gxBlendFn_800789ac();
    gSunFlareScissorWidth = 0;
    gSunFlareScissorHeight = 0;
    sky = skyFn_8008919c(2);
    if (sky != 0 && (renderFlags & 0x40))
    {
        void* viewMtx = Camera_GetViewMatrix();
        fn_800897D4(0, &dir[0], &dir[1], &dir[2]);
        cam[0] = *(f32*)((char*)viewMtx + 0x20);
        cam[1] = *(f32*)((char*)viewMtx + 0x24);
        cam[2] = *(f32*)((char*)viewMtx + 0x28);
        sunDot = PSVECDotProduct(dir, cam);
        if (sunDot > lbl_803DEBCC)
        {
            int occ;
            int i;
            f32 fade;
            skyBuildSunModelMatrix(sunMtx);
            Camera_ProjectWorldPointWithOffset(sunMtx[3], sunMtx[7], sunMtx[11], lbl_803DEBD4, &px, &py, &pz);
            Camera_NdcToScreen(px, py, pz, &sx, &sy, &sz);
            gSunFlareScissorX = sx - 0x10;
            gSunFlareScissorWidth = 0x20;
            gSunFlareScissorY = sy - 0x10;
            gSunFlareScissorHeight = 0x20;
            if ((int)gSunFlareScissorX < 0)
                gSunFlareScissorX = 0;
            else if ((int)gSunFlareScissorX > 0x280)
                gSunFlareScissorX = 0x280;
            if ((int)gSunFlareScissorY < 0)
                gSunFlareScissorY = 0;
            else if ((int)gSunFlareScissorY > 0x1e0)
                gSunFlareScissorY = 0x1e0;
            if ((int)gSunFlareScissorX + 0x20 > 0x280)
                gSunFlareScissorWidth = 0x280 - gSunFlareScissorX;
            if ((int)gSunFlareScissorY + 0x20 > 0x1e0)
                gSunFlareScissorHeight = 0x1e0 - gSunFlareScissorY;
            occ = 0;
            for (i = 0; i < 5; i++)
            {
                int d = depthReadRequestPoll(sx + gSunOcclusionSampleOffsets[i * 2], sy + gSunOcclusionSampleOffsets[i * 2 + 1], (void*)i);
                if (sz <= d && pauseMenuGetState() == 0)
                    occ++;
            }
            fade = (f32)(u32)
            occ / flushFlag_803DEBE4 - gSunFlareFade;
            if (fade > Initialized_803DEC30)
                fade = Initialized_803DEC30;
            else if (fade < EnabledBits_803DEC34)
                fade = EnabledBits_803DEC34;
            gSunFlareFade = gSunFlareFade + fade;
            sunDot = sunDot * gSunFlareFade;
            if (sunDot > lbl_803DEBCC)
            {
                u8 ar, ag, ab;
                PSMTXConcat(viewMtx, sunMtx, sunMtx);
                GXLoadPosMtxImm(sunMtx, 0);
                GXSetCurrentMtx(0);
                fn_8008912C();
                selectTexture(0, 0);
                getAmbientColor(0, &ar, &ag, &ab);
                sunDot = (f32)(u32)
                sky * sunDot;
                _gxSetTevColor2(ar, ag, ab, (int)(displayOffsetH_803DEBFC * sunDot));
                alpha = (int)(lbl_803DEBD8 - ResettingBits_803DEC38 * sunDot);
                sunDot = RecalibrateBits_803DEC3C * sunDot * WaitingBits_803DEC40;
                GXBegin(0x80, 2, 4);
                GXWGFifo.f32 = -sunDot;
                GXWGFifo.f32 = -sunDot;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = sunDot;
                GXWGFifo.f32 = -sunDot;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = sunDot;
                GXWGFifo.f32 = sunDot;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = -sunDot;
                GXWGFifo.f32 = sunDot;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBDC;
            }
        }
    }
    colorScale = alpha;
    if (lbl_803DCE06 != 0)
    {
        int i;
        for (i = 0; i < lbl_803DCE06; i++)
        {
            ModelLightStruct* e = (ModelLightStruct*)gGlowLightList[i];
            int d;
            Camera_ProjectWorldPointWithOffset(e->worldX - playerMapOffsetX, e->worldY,
                                               e->worldZ - playerMapOffsetZ,
                                               e->glowProjectionRadius, &px, &py, &pz);
            Camera_NdcToScreen(px, py, pz, &sx, &sy, &sz);
            d = depthReadRequestPoll(sx, sy, e);
            if (sz <= d && pauseMenuGetState() == 0)
                e->glowAlphaStep = 0x10;
            else
                e->glowAlphaStep = -0x10;
        }
        GXSetCurrentMtx(0x3c);
        gxTextureFn_800794e0();
        gxBlendFn_800789ac();
        for (i = 0; i < lbl_803DCE06; i++)
        {
            ModelLightStruct* e = (ModelLightStruct*)gGlowLightList[i];
            if (e->glowAlpha != 0)
            {
                f32 f = e->activeIntensity;
                f32 cx, cy, cz, hs;
                selectTexture((int)e->glowTexture, 0);
                _gxSetTevColor2((int)((f32)(u32)e->glowColor[0] * f),
                    (int)
                ((f32)(u32)
                e->glowColor[1] * f
                )
                ,
                (int)
                ((f32)(u32)
                e->glowColor[2] * f
                )
                ,
                (e->glowColor[3] * e->glowAlpha) >> 8 & 0xff
                )
                ;
                GXBegin(0x80, 2, 4);
                cx = e->viewX;
                cy = e->viewY;
                cz = e->viewZ;
                hs = e->glowScale;
                GXWGFifo.f32 = cx - hs;
                GXWGFifo.f32 = cy - hs;
                GXWGFifo.f32 = cz;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = cx + hs;
                GXWGFifo.f32 = cy - hs;
                GXWGFifo.f32 = cz;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = cx + hs;
                GXWGFifo.f32 = cy + hs;
                GXWGFifo.f32 = cz;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = lbl_803DEBDC;
                GXWGFifo.f32 = cx - hs;
                GXWGFifo.f32 = cy + hs;
                GXWGFifo.f32 = cz;
                GXWGFifo.f32 = lbl_803DEBCC;
                GXWGFifo.f32 = lbl_803DEBDC;
            }
        }
        GXSetCurrentMtx(0);
    }
}

void gxErrorFn_80060b40(void)
{
    int n;
    int i;

    i = 0;
    n = lbl_803DCE98;
    for (; i < n; i++)
    {
    }
}

extern f32 lbl_8038D77C[];
extern const f32 lbl_803DECA0;
extern const f32 lbl_803DECA4;
extern const f32 lbl_803DECA8;
extern const f32 lbl_803DECAC;
extern void fn_8006D5E8(void);

void initTextures(void)
{
    f32* a = lbl_8038D77C;
    f32* b = lbl_8038D7DC;

    gShadowFlag = 10;
    gShadowVolumeBuffer = (int)mmAlloc(0xa8c0, 0x18, 0);
    a[0] = __AR_init_flag;
    b[0] = __AR_init_flag;
    a[1] = __AR_init_flag;
    b[1] = __AR_init_flag;
    a[2] = __AR_init_flag;
    b[2] = __AR_init_flag;
    a[3] = __AR_init_flag;
    b[3] = __AR_init_flag;
    a[4] = lbl_803DEC58;
    b[4] = lbl_803DEC58;
    a[5] = __AR_init_flag;
    b[5] = __AR_init_flag;
    a[6] = lbl_803DEC68;
    b[6] = lbl_803DEC68;
    a[7] = lbl_803DEC58;
    b[7] = lbl_803DEC58;
    a[8] = __AR_init_flag;
    b[8] = __AR_init_flag;
    a[9] = lbl_803DEC68;
    b[9] = lbl_803DEC68;
    a[10] = __AR_init_flag;
    b[10] = __AR_init_flag;
    a[11] = __AR_init_flag;
    b[11] = __AR_init_flag;
    b[12] = __AR_init_flag;
    b[13] = __AR_init_flag;
    b[14] = lbl_803DEC68;
    b[15] = __AR_init_flag;
    b[16] = lbl_803DEC58;
    b[17] = lbl_803DEC68;
    b[18] = lbl_803DEC68;
    b[19] = lbl_803DEC58;
    b[20] = lbl_803DEC68;
    b[21] = lbl_803DEC68;
    b[22] = __AR_init_flag;
    b[23] = lbl_803DEC68;
    a[12] = lbl_803DECA0;
    a[13] = lbl_803DEC58;
    a[14] = lbl_803DECA4;
    a[15] = lbl_803DECA0;
    a[16] = lbl_803DECA8;
    a[17] = lbl_803DECA4;
    a[18] = lbl_803DECAC;
    a[19] = lbl_803DECA8;
    a[20] = lbl_803DECA4;
    a[21] = lbl_803DECAC;
    a[22] = lbl_803DEC58;
    a[23] = lbl_803DECA4;
    fn_8006D5E8();
}

extern int doLotsOfMath(void* a, void* b, int c, void* d, int* e, int g, int h, int i, int self, f32 f);
extern char sTrackNoFreeLastLineError[];
extern u8 lbl_803DCF4C;

void objBboxFn_800640cc(f32* p0, f32* p1, f32 f, int p5, int* out, int* self, int p8, int p9, int slot, u8 arg8)
{
    f32 w0[3];
    f32 w1[3];
    f32 t20[3];
    f32 t14[3];
    int* objs;
    int count;
    int i;
    int mtx;

    lbl_803DCF4C = 0;
    if (out != NULL)
    {
        *(s8*)((char*)out + 0x50) = -1;
        *(s8*)((char*)out + 0x51) = -1;
    }
    mtx = (self != NULL) ? *(int*)((char*)self + 0x30) : 0;
    if ((u32)mtx != 0)
    {
        Obj_TransformLocalPointToWorld(p0[0], p0[1], p0[2], &w0[0], &w0[1], &w0[2], mtx);
        Obj_TransformLocalPointToWorld(p1[0], p1[1], p1[2], &w1[0], &w1[1], &w1[2], mtx);
    }
    else
    {
        memcpy(w0, p0, 0xc);
        memcpy(w1, p1, 0xc);
    }
    objs = ObjGroup_GetObjects(6, &count);
    for (i = 0; i < count; i++, objs++)
    {
        int* o = (int*)*objs;
        int* p54;
        int hdr;
        f32 rad;
        f32 dx, dy, dz;
        s8 hit;
        int* e;
        s16 k;

        if (o == self) continue;
        if ((s8) * (u8*)((char*)o + 0x35) <= -1) continue;
        if (*(u32*)(*(int*)&((GameObject*)o)->anim.modelInstance + 0x34) == 0) continue;
        p54 = *(int**)&((GameObject*)o)->anim.hitReactState;
        if (p54 != NULL && (((ObjHitsPriorityState*)p54)->flags & 1) == 0) continue;
        dx = ((GameObject*)o)->anim.localPosX - w0[0];
        dy = ((GameObject*)o)->anim.localPosY - w0[1];
        dz = ((GameObject*)o)->anim.localPosZ - w0[2];
        hdr = *(int*)(*(int*)(*(int*)&((GameObject*)o)->anim.banks
            + (s8)((ObjHitsPriorityState*)p54)->stateIndex * 4));
        rad = (f32)((u16)modelFileHeaderGetCullDistance((void*)hdr) + 0x32);
        rad = rad * rad;
        hit = 0;
        {
            f32 ddy = dy * dy;
            if (ddy + dx * dx + dz * dz < rad) hit = 1;
        }
        if (hit == 0)
        {
            f32 ex = ((GameObject*)o)->anim.localPosX - w1[0];
            f32 ey = ((GameObject*)o)->anim.localPosY - w1[1];
            f32 ez = ((GameObject*)o)->anim.localPosZ - w1[2];
            if (ey * ey + ex * ex + ez * ez < rad) hit = 1;
        }
        if (hit == 0) continue;
        if ((u8)slot != 0xff)
        {
            char* fl;
            k = 0;
            fl = (char*)gMapDynamicSlots;
            do
            {
                if (*(u8*)(fl + 0x14) != 0 && *(u32*)fl == (u32)self &&
                    *(u32*)(fl + 4) == (u32)o && *(u8*)(fl + 0x15) == (u8)slot)
                {
                    *(u8*)(fl + 0x14) = 0;
                    e = (int*)fl;
                    goto haveEntry;
                }
                fl += 0x18;
                k++;
            }
            while (k < 0x40);
        }
        e = NULL;
    haveEntry:
        if (e != NULL)
        {
            t20[0] = ((ModelLightStruct*)e)->localY;
            t20[1] = ((ModelLightStruct*)e)->localZ;
            t20[2] = ((ModelLightStruct*)e)->worldX;
        }
        else
        {
            Obj_TransformWorldPointToLocal(w0[0], w0[1], w0[2], &t20[0], &t20[1], &t20[2], (u32)o);
        }
        Obj_TransformWorldPointToLocal(w1[0], w1[1], w1[2], &t14[0], &t14[1], &t14[2], (u32)o);
        if (doLotsOfMath(t20, t14, p5, out, o, p8, p9, arg8, (int)self, f) != 0)
            Obj_TransformLocalPointToWorld(t14[0], t14[1], t14[2], &w1[0], &w1[1], &w1[2], (u32)o);
        if ((u8)slot != 0xff)
        {
            char* fl;
            k = 0;
            fl = (char*)gMapDynamicSlots;
            do
            {
                if (*(u8*)(fl + 0x14) == 0)
                {
                    *(int*)fl = (int)self;
                    *(int*)(fl + 4) = (int)o;
                    *(u8*)(fl + 0x15) = slot;
                    *(u8*)(fl + 0x14) = 2;
                    e = (int*)fl;
                    goto stored;
                }
                fl += 0x18;
                k++;
            }
            while (k < 0x40);
            e = NULL;
        stored:
            if (e == NULL)
            {
                debugPrintf(sTrackNoFreeLastLineError);
            }
            if (e != NULL)
            {
                ((ModelLightStruct*)e)->localY = t14[0];
                ((ModelLightStruct*)e)->localZ = t14[1];
                ((ModelLightStruct*)e)->worldX = t14[2];
            }
        }
    }
    doLotsOfMath(w0, w1, p5, out, NULL, p8, p9, arg8, (int)self, f);
    if (lbl_803DCF4C != 0 && out != NULL)
    {
        f32 hx = *(f32*)((char*)out + 0x3c) - *(f32*)((char*)out + 0xc);
        f32 hy = *(f32*)((char*)out + 0x40) - *(f32*)((char*)out + 0x10);
        f32 len;
        *(f32*)((char*)out + 0x2c) = *(f32*)((char*)out + 0x18) - *(f32*)((char*)out + 0x14);
        *(f32*)((char*)out + 0x30) = __AR_Callback;
        *(f32*)((char*)out + 0x34) = *(f32*)((char*)out + 0x4) - *(f32*)((char*)out + 0x8);
        len = lbl_803DECC4 / sqrtf(*(f32*)((char*)out + 0x2c) * *(f32*)((char*)out + 0x2c) +
            *(f32*)((char*)out + 0x34) * *(f32*)((char*)out + 0x34));
        *(f32*)((char*)out + 0x2c) = *(f32*)((char*)out + 0x2c) * len;
        *(f32*)((char*)out + 0x34) = *(f32*)((char*)out + 0x34) * len;
        *(f32*)((char*)out + 0x38) = *(f32*)((char*)out + 0x34) * *(f32*)((char*)out + 0x14) -
            *(f32*)((char*)out + 0x2c) * *(f32*)((char*)out + 0x4);
        if (*(int*)out != 0)
        {
            Obj_TransformLocalPointToWorld(*(f32*)((char*)out + 4), *(f32*)((char*)out + 0xc),
                                           *(f32*)((char*)out + 0x14), (f32*)((int)out + 4),
                                           (f32*)((int)out + 0xc), (f32*)((int)out + 0x14),
                                           (u32)*(int*)out);
            Obj_TransformLocalPointToWorld(*(f32*)((char*)out + 8), *(f32*)((char*)out + 0x10),
                                           *(f32*)((char*)out + 0x18), (f32*)((int)out + 8),
                                           (f32*)((int)out + 0x10), (f32*)((int)out + 0x18),
                                           (u32)*(int*)out);
        }
        if ((u32)mtx != 0)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((char*)out + 4), *(f32*)((char*)out + 0xc),
                                           *(f32*)((char*)out + 0x14), (f32*)((int)out + 4),
                                           (f32*)((int)out + 0xc), (f32*)((int)out + 0x14),
                                           mtx);
            Obj_TransformWorldPointToLocal(*(f32*)((char*)out + 8), *(f32*)((char*)out + 0x10),
                                           *(f32*)((char*)out + 0x18), (f32*)((int)out + 8),
                                           (f32*)((int)out + 0x10), (f32*)((int)out + 0x18),
                                           mtx);
        }
        *(f32*)((char*)out + 0x1c) = *(f32*)((char*)out + 0x18) - *(f32*)((char*)out + 0x14);
        *(f32*)((char*)out + 0x20) = __AR_Callback;
        *(f32*)((char*)out + 0x24) = *(f32*)((char*)out + 0x4) - *(f32*)((char*)out + 0x8);
        len = lbl_803DECC4 / sqrtf(*(f32*)((char*)out + 0x1c) * *(f32*)((char*)out + 0x1c) +
            *(f32*)((char*)out + 0x24) * *(f32*)((char*)out + 0x24));
        *(f32*)((char*)out + 0x1c) = *(f32*)((char*)out + 0x1c) * len;
        *(f32*)((char*)out + 0x24) = *(f32*)((char*)out + 0x24) * len;
        *(f32*)((char*)out + 0x3c) = *(f32*)((char*)out + 0xc) + hx;
        *(f32*)((char*)out + 0x40) = *(f32*)((char*)out + 0x10) + hy;
        *(f32*)((char*)out + 0x28) = *(f32*)((char*)out + 0x24) * *(f32*)((char*)out + 0x14) -
            *(f32*)((char*)out + 0x1c) * *(f32*)((char*)out + 0x4);
    }
    if (lbl_803DCF4C != 0)
    {
        if ((u32)mtx != 0)
            Obj_TransformWorldPointToLocal(w1[0], w1[1], w1[2], &p1[0], &p1[1], &p1[2], mtx);
        else
            memcpy(p1, w1, 0xc);
    }
}

/* fn_80067B84 -- gather model triangles overlapping a swept bbox into the
 * hit-detect triangle buffer at cur (0x4c-byte records); returns advanced
 * cursor. */
extern u8* fn_80028364(int hdr, int i);
extern u16* fn_80028354(int hdr, int tri);
extern s16* ObjModel_GetBaseVertexCoords(int hdr, u32 idx);
extern const f32 lbl_803DECF0;
extern const f32 lbl_803DECF4;
extern const f32 lbl_803DECF8;

int fn_80067B84(int cur, TrackBlockDescriptor* desc, int model, int flags, f32 scale,
                f32 x0, f32 y0d, f32 z0, f32 x1, f32 y1d, f32 z1)
{
    f32 xd, xc, xb, xa;
    f32 zd, zc, zb, za;
    f32 ytmp;
    f32 y1, y0;
    int count, i;
    int flag8, flag20;
    int flag4;
    int hdr;
    int maxYi, minYi;

    y0 = y0d;
    y1 = y1d;
    hdr = *(int*)model;

    Matrix_TransformPoint(desc->currentMatrix, x0, y0d, z0, &xa, &ytmp, &za);
    Matrix_TransformPoint(desc->currentMatrix, x0, y0, z1, &xb, &y0, &zb);
    Matrix_TransformPoint(desc->currentMatrix, x1, y1, z0, &xc, &ytmp, &zc);
    Matrix_TransformPoint(desc->currentMatrix, x1, y1, z1, &xd, &y1, &zd);

    x1 = xa;
    x0 = x1;
    z1 = za;
    z0 = z1;
    if (xb < x1) x0 = xb;
    if (xb > x1) x1 = xb;
    if (zb < z0) z0 = zb;
    if (zb > z1) z1 = zb;
    if (xc < x0) x0 = xc;
    if (xc > x1) x1 = xc;
    if (zc < z0) z0 = zc;
    if (zc > z1) z1 = zc;
    if (xd < x0) x0 = xd;
    if (xd > x1) x1 = xd;
    if (zd < z0) z0 = zd;
    if (zd > z1) z1 = zd;

    count = *(u16*)(hdr + 0xf0);
    i = 0;
    flag20 = (u8)flags & 0x20;
    flag8 = (u8)flags & 8;
    flag4 = (u8)flags & 4;

    for (; i < count; i++)
    {
        u8* blk = fn_80028364(hdr, i);
        s16* bs = (s16*)blk;
        u32 bf = *(u32*)(blk + 0x10);
        int tEnd, t;

        if (bf & 0x100000) continue;
        if ((bf & 0x8000000) && flag20 == 0) continue;
        if (x0 > bs[2] * scale) continue;
        if (x1 < bs[1] * scale) continue;
        if (y0 > bs[4] * scale) continue;
        if (y1 < bs[3] * scale) continue;
        if (z0 > bs[6] * scale) continue;
        if (z1 < bs[5] * scale) continue;

        tEnd = *(u16*)(blk + 0x14);
        t = *(u16*)blk;
        for (; t < tEnd; t++)
        {
            u16* tw = fn_80028354(hdr, t);
            f32 tMinX, tMaxX, tMinY, tMaxY, tMinZ, tMaxZ;
            int j;
            u8* vout;
            s16 *xs, *ys, *zs;
            int nxi, nyi, nzi;
            f32 fnx, fny, fnz;
            f32 len, inv;

            tMinX = lbl_803DECF0;
            tMaxX = lbl_803DECF4;
            tMinY = tMinX;
            tMaxY = tMaxX;
            tMinZ = tMinX;
            tMaxZ = tMaxX;
            j = 0;
            vout = (u8*)cur;
            for (; j < 3; j++)
            {
                s16* v = ObjModel_GetBaseVertexCoords(hdr, *tw);
                f32 fx, fy, fz;
                if (*(u16*)(hdr + 2) & 0x800)
                {
                    fx = v[0] * scale;
                    fy = v[1] * scale;
                    fz = v[2] * scale;
                }
                else
                {
                    fx = v[0] * scale * lbl_803DECF8;
                    fy = v[1] * scale * lbl_803DECF8;
                    fz = v[2] * scale * lbl_803DECF8;
                }
                if (fx > tMaxX) tMaxX = fx;
                if (fx < tMinX) tMinX = fx;
                if (fy > tMaxY)
                {
                    tMaxY = fy;
                    maxYi = j;
                }
                if (fy < tMinY)
                {
                    tMinY = fy;
                    minYi = j;
                }
                if (fz > tMaxZ) tMaxZ = fz;
                if (fz < tMinZ) tMinZ = fz;
                *(s16*)(vout + 0x10) = fx;
                *(s16*)(vout + 0x16) = fy;
                *(s16*)(vout + 0x1c) = fz;
                tw++;
                vout += 2;
            }
            if (tMinY > y1) continue;
            if (tMaxY < y0) continue;
            if (tMinX > x1) continue;
            if (tMaxX < x0) continue;
            if (tMinZ > z1) continue;
            if (tMaxZ < z0) continue;

            xs = (s16*)(cur + 0x10);
            ys = (s16*)(cur + 0x16);
            zs = (s16*)(cur + 0x1c);

            nxi = ys[0] * (zs[1] - zs[2]) + (ys[1] * (zs[2] - zs[0]) + ys[2] * (zs[0] - zs[1]));
            fnx = nxi;
            nyi = zs[0] * (xs[1] - xs[2]) + (zs[1] * (xs[2] - xs[0]) + zs[2] * (xs[0] - xs[1]));
            fny = nyi;
            nzi = xs[0] * (ys[1] - ys[2]) + (xs[1] * (ys[2] - ys[0]) + xs[2] * (ys[0] - ys[1]));
            fnz = nzi;
            len = sqrtf(fnz * fnz + (fnx * fnx + fny * fny));
            if (len <= __AR_Callback) continue;
            inv = lbl_803DECC4 / len;
            *(f32*)(cur + 4) = fnx * inv;
            *(f32*)(cur + 8) = fny * inv;
            *(f32*)(cur + 0xc) = fnz * inv;

            if (flag8)
            {
                if (*(f32*)(cur + 8) >= __AR_Size) continue;
                if (*(f32*)(cur + 8) <= lbl_803DECEC) continue;
            }
            if (flag4)
            {
                if (*(f32*)(cur + 8) < __AR_Size && *(f32*)(cur + 8) > lbl_803DECEC) continue;
            }

            *(f32*)(cur + 0) = -(*(f32*)(cur + 0xc) * zs[0]
                + (*(f32*)(cur + 4) * xs[0] + *(f32*)(cur + 8) * ys[0]));

            {
                int k22 = 0;
                int deg = 0;
                int j2 = 0;
                s16* xw = xs;
                s16* yw = ys;
                s16* zw = zs;
                f32 eps = __AR_Callback;
                for (; j2 < 3; j2++)
                {
                    int k = j2 + 1;
                    f32 px, py, pz;
                    f32 ex, ey, ez;
                    if (k > 2) k = 0;
                    px = *(f32*)(cur + 4) + xw[0];
                    py = *(f32*)(cur + 8) + yw[0];
                    pz = *(f32*)(cur + 0xc) + zw[0];
                    ex = py * (f32)(zw[0] - zs[k]) + ((f32)yw[0] * ((f32)zs[k] - pz) + ys[k] * (pz - zw[0]));
                    ey = pz * (f32)(xw[0] - xs[k]) + ((f32)zw[0] * ((f32)xs[k] - px) + zs[k] * (px - xw[0]));
                    ez = px * (f32)(yw[0] - ys[k]) + ((f32)xw[0] * ((f32)ys[k] - py) + xs[k] * (py - yw[0]));
                    len = sqrtf(ez * ez + (ex * ex + ey * ey));
                    if (len <= eps)
                    {
                        deg = 1;
                    }
                    else
                    {
                        f32 inv2 = lbl_803DECC4 / len;
                        ex *= inv2;
                        ey *= inv2;
                        ez *= inv2;
                    }
                    *(f32*)(cur + k22 * 4 + 0x24) = ex;
                    k22++;
                    *(f32*)(cur + k22 * 4 + 0x24) = ey;
                    k22++;
                    *(f32*)(cur + k22 * 4 + 0x24) = ez;
                    k22++;
                    xw++;
                    yw++;
                    zw++;
                }
                if (deg) continue;
            }

            *(s8*)(cur + 0x48) = (u8)fn_80060668((int*)blk);
            *(u8*)(cur + 0x4a) = (u8)((maxYi << 4) | minYi);
            *(s8*)(cur + 0x49) = 10;
            *(s8*)(cur + 0x49) |= 8;
            cur += 0x4c;
            if ((u32)cur >= gTrackTriangleBufferEnd)
            {
                return cur;
            }
        }
    }
    return cur;
}

/* mapLoadBlocksFn_800685cc -- gather map-block collision triangles overlapping
 * the query box into the buffer at cur; returns advanced cursor. */
extern u8* mapGetBlockAtPos(int x, int z, int layer);
extern int cacheAllocAndCopy(void* p, int size, int* offIn, int* offOut, int base);
extern float fastFloorf(float x);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern f32 PSVECMag(f32 * v);
extern int lbl_803DCDC8;
extern int lbl_803DCDCC;

#pragma ppc_unroll_instructions_limit 16
int mapLoadBlocksFn_800685cc(cur, x0, y0, z0, x1, y1, z1, flags, doEdges)
int cur;
int x0;
int y0;
int z0;
int x1;
int y1;
int z1;
int flags;

u8 doEdges;
{
    int cells[16];
    f32 e2[3];
    f32 e1[3];
    f32 e0[3];
    f32 verts[6];
    f32 v0[3];
    f32 en[3];
    int offA;
    int offB;
    int offC;
    int gx0, gz0, gx1, gz1;
    int count, layer;
    int *cellp, *cw;
    int *descp, *dw;
    int* firstp;
    int f40, f80, f200, f120, f20, f8, f100, f4;
    int last, i;
    int dmaflip;
    u8 typeb;

    x0 = x0 - lbl_803DCDC8;
    z0 = z0 - lbl_803DCDCC;
    x1 = x1 - lbl_803DCDC8;
    z1 = z1 - lbl_803DCDCC;
    if (x0 > x1)
    {
        x0 ^= x1;
        x1 ^= x0;
        x0 ^= x1;
    }
    if (z0 > z1)
    {
        z0 ^= z1;
        z1 ^= z0;
        z0 ^= z1;
    }
    gx0 = fastFloorf((f32)x0 / lbl_803DECE0[0]);
    gz0 = fastFloorf((f32)z0 / lbl_803DECE0[0]);
    gx1 = fastFloorf((f32)x1 / lbl_803DECE0[0]);
    gz1 = fastFloorf((f32)z1 / lbl_803DECE0[0]);

    count = 0;
    layer = 0;
    cellp = cells;
    cw = cellp;
    descp = (int*)gTrackGridOrigin;
    dw = descp;
    do
    {
        int gx, gz;
        int *p1, *q1, *p2, *q2;
        p1 = cw;
        q1 = dw;
        for (gx = gx0; gx <= gx1 && count < 16; gx++)
        {
            p2 = p1;
            q2 = q1;
            for (gz = gz0; gz <= gz1 && count < 16; gz++)
            {
                u8* blk = mapGetBlockAtPos(gx, gz, layer);
                if (blk != NULL)
                {
                    *p2 = (int)blk;
                    q2[0] = gx * 0x280;
                    q2[2] = gz * 0x280;
                    p2++;
                    q2 += 3;
                    p1++;
                    q1 += 3;
                    cw++;
                    dw += 3;
                    count++;
                }
            }
        }
        layer++;
    }
    while (layer < 5);

    if (count == 0)
    {
        return cur;
    }

    {
        int c0 = cells[0];
        void* p = fn_800606DC((int*)c0, 0);
        dmaflip = 0;
        offA = 0;
        cacheAllocAndCopy(p, *(u16*)(c0 + 0x98) << 3, &offA, &offB, 0x2000);
        cacheAllocAndCopy(*(void**)(c0 + 0x58), *(u16*)(c0 + 0x90) * 6, &offB, &offC, 0x2000);
    }
    i = 0;
    firstp = (int*)gTrackGridOrigin;
    f40 = (u16)flags & 0x40;
    f80 = (u16)flags & 0x80;
    f200 = (u16)flags & 0x200;
    f120 = (u16)flags & 0x120;
    f20 = (u16)flags & 0x20;
    f8 = (u16)flags & 8;
    f100 = (u16)flags & 0x100;
    f4 = (u16)flags & 4;
    last = count - 1;
    for (; i < count; i++)
    {
        int bb;
        int vb;
        int blk;
        int relx0, relx1, relz0, relz1;
        int dxoff, dzoff;
        int mask;
        u32 bit;
        int pos, k;
        int mask16;
        u8* tri;
        u32 triEnd;

        bb = offA;
        vb = offB;
        if (i < last)
        {
            int next = cellp[1];
            int nextBase;
            void* p;
            int c13, c14;
            dmaflip ^= 0x2000;
            nextBase = dmaflip + 0x2000;
            p = fn_800606DC((int*)next, 0);
            offA = dmaflip;
            c13 = cacheAllocAndCopy(p, *(u16*)(next + 0x98) << 3, &offA, &offB, nextBase);
            c14 = cacheAllocAndCopy(*(void**)(next + 0x58), *(u16*)(next + 0x90) * 6, &offB, &offC, nextBase);
            cacheQueueWait((u8)(c13 + c14));
        }
        else
        {
            cacheQueueWait(0);
        }

        blk = *cellp;
        relx0 = x0 - descp[0];
        relx1 = x1 - descp[0];
        relz0 = z0 - descp[2];
        relz1 = z1 - descp[2];
        descp[0] = descp[0] + lbl_803DCDC8;
        descp[2] = descp[2] + lbl_803DCDCC;
        if (relx0 < 0) relx0 = 0;
        if (relx1 > 0x280) relx1 = 0x280;
        if (relz0 < 0) relz0 = 0;
        if (relz1 > 0x280) relz1 = 0x280;
        dxoff = descp[0] - firstp[0];
        dzoff = descp[2] - firstp[2];

        mask = 0;
        bit = 1;
        pos = 0;
        for (k = 2; k != 0; k--)
        {
            if (relx0 <= pos + 0x50 && relx1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relx0 <= pos + 0x50 && relx1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relx0 <= pos + 0x50 && relx1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relx0 <= pos + 0x50 && relx1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
        }
        pos = 0;
        for (k = 2; k != 0; k--)
        {
            if (relz0 <= pos + 0x50 && relz1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relz0 <= pos + 0x50 && relz1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relz0 <= pos + 0x50 && relz1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
            if (relz0 <= pos + 0x50 && relz1 >= pos) mask |= bit;
            bit = (s16)(bit << 1);
            pos += 0x50;
        }
        tri = *(u8**)(blk + 0x50);
        triEnd = (u32)tri + *(u16*)(blk + 0x9a) * 0x14;
        mask16 = (s16)mask;
        for (; (u32)tri < triEnd; tri += 0x14)
        {
            u32 tf = *(u32*)(tri + 0x10);
            u8 type;
            int yoff;
            int t0, vEnd;
            u8* vq;

            if ((tf & 0x10) && f40) continue;
            if (!(tf & 4) && f80) continue;
            if (tf & 8)
            {
                if (tf & 1) continue;
                if (f200) continue;
                type = 4;
                if (f120 == 0) type |= 0x10;
            }
            else
            {
                if ((tf & 2) && f20 == 0) continue;
                type = 2;
            }
            yoff = *(s16*)(blk + 0x8e);
            if (*(s16*)(tri + 6) + yoff > y1) continue;
            if (*(s16*)(tri + 8) + yoff < y0) continue;
            if (*(s16*)(tri + 2) > relx1) continue;
            if (*(s16*)(tri + 4) < relx0) continue;
            if (*(s16*)(tri + 0xa) > relz1) continue;
            if (*(s16*)(tri + 0xc) < relz0) continue;
            if (tf & 4) type |= 8;
            typeb = fn_80060668((int*)tri);
            t0 = *(u16*)tri;
            vq = (u8*)(bb + t0 * 8);
            vEnd = *(u16*)(tri + 0x14);
            for (; t0 < vEnd; t0++, vq += 8)
            {
                s16* vp;
                int minX, maxX, minY, maxY, minZ, maxZ;
                u8 maxYi, minYi;
                u16* tw;
                u8* vo;
                f32* vf;
                int j;
                f32 mag;

                if ((mask16 & *(u16*)(vq + 6) & 0xff) == 0) continue;
                if ((mask16 & *(u16*)(vq + 6) & 0xff00) == 0) continue;
                vp = (s16*)(vb + *(u16*)vq * 6);
                minX = vp[0] >> 3;
                maxX = minX;
                minY = (vp[1] >> 3) + *(s16*)(blk + 0x8e);
                maxY = minY;
                minZ = vp[2] >> 3;
                maxZ = minZ;
                *(s16*)(cur + 0x10) = minX + dxoff;
                *(s16*)(cur + 0x16) = minY;
                *(s16*)(cur + 0x1c) = minZ + dzoff;
                v0[0] = __OSs16tof32((s16*)(cur + 0x10));
                v0[1] = __OSs16tof32((s16*)(cur + 0x16));
                v0[2] = __OSs16tof32((s16*)(cur + 0x1c));
                maxYi = 0;
                minYi = 0;
                tw = (u16*)(vq + 2);
                vo = (u8*)(cur + 2);
                vf = verts;
                for (j = 1; j < 3; j++)
                {
                    int x, yy, z;
                    vp = (s16*)(vb + *tw * 6);
                    x = vp[0] >> 3;
                    yy = (vp[1] >> 3) + *(s16*)(blk + 0x8e);
                    z = vp[2] >> 3;
                    if (x > maxX) maxX = x;
                    else if (x < minX) minX = x;
                    if (yy > maxY)
                    {
                        maxY = yy;
                        maxYi = j;
                    }
                    else if (yy < minY)
                    {
                        minY = yy;
                        minYi = j;
                    }
                    if (z > maxZ) maxZ = z;
                    else if (z < minZ) minZ = z;
                    *(s16*)(vo + 0x10) = x + dxoff;
                    *(s16*)(vo + 0x16) = yy;
                    *(s16*)(vo + 0x1c) = z + dzoff;
                    vf[0] = __OSs16tof32((s16*)(vo + 0x10));
                    vf[1] = __OSs16tof32((s16*)(vo + 0x16));
                    vf[2] = __OSs16tof32((s16*)(vo + 0x1c));
                    tw++;
                    vo += 2;
                    vf += 3;
                }
                if (minY > y1) continue;
                if (maxY < y0) continue;
                if (minX > relx1) continue;
                if (maxX < relx0) continue;
                if (minZ > relz1) continue;
                if (maxZ < relz0) continue;

                PSVECSubtract(v0, verts, e0);
                PSVECSubtract(verts, verts + 3, e1);
                PSVECCrossProduct(e0, e1, (f32*)(cur + 4));
                mag = PSVECMag((f32*)(cur + 4));
                if (!(mag > __AR_Callback)) continue;
                {
                    f32 inv = lbl_803DECC4 / mag;
                    PSVECScale((f32*)(cur + 4), (f32*)(cur + 4), inv);
                }
                if (f8)
                {
                    if (*(f32*)(cur + 8) >= __AR_Size || *(f32*)(cur + 8) <= lbl_803DECEC)
                    {
                        if (type != 4) continue;
                        if (f100 == 0) continue;
                    }
                }
                if (f4)
                {
                    if (*(f32*)(cur + 8) < __AR_Size && *(f32*)(cur + 8) > lbl_803DECEC) continue;
                }
                *(f32*)cur = -PSVECDotProduct((f32*)(cur + 4), v0);
                if (doEdges)
                {
                    int k22, deg, j2;
                    f32* ep;
                    f32 one = lbl_803DECC4;
                    f32 eps = __AR_Callback;
                    PSVECSubtract(verts + 3, v0, e2);
                    k22 = 0;
                    deg = 0;
                    j2 = 0;
                    ep = e0;
                    do
                    {
                        f32 m;
                        PSVECCrossProduct((f32*)(cur + 4), ep, en);
                        m = PSVECMag(en);
                        if (m > eps)
                        {
                            f32 inv = one / m;
                            PSVECScale(en, en, inv);
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[0];
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[1];
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[2];
                        }
                        else
                        {
                            deg = 1;
                            break;
                        }
                        ep += 3;
                        j2++;
                    }
                    while (j2 < 3);
                    if (deg) continue;
                }
                {
                    u32 tf2 = *(u32*)(tri + 0x10);
                    u8 t2;
                    if (tf2 & 8)
                    {
                        t2 = 0xe;
                    }
                    else
                    {
                        t2 = typeb;
                    }
                    if (tf2 & 0x20) type |= 0x40;
                    *(s8*)(cur + 0x48) = t2;
                    *(u8*)(cur + 0x4a) = (u8)((maxYi << 4) | minYi);
                    *(s8*)(cur + 0x49) = type;
                    cur += 0x4c;
                    if ((u32)cur >= gTrackTriangleBufferEnd)
                    {
                        return cur;
                    }
                }
            }
        }
        cellp++;
        descp += 3;
    }
    return cur;
}
#pragma ppc_unroll_instructions_limit 64

/* trackIntersect -- rebuild the intersection line table from map blocks when
 * a refresh has been requested. */
extern u8* mapGetBlockIdx(int layer);
extern void* mapGetBlock(int i);
extern int getHudHiddenFrameCount(void);
extern u8 lbl_803DCF44;
extern int lbl_803DCF40;

void trackIntersect(void)
{
    s16 counts[0x47];
    s16 edges[0x6a4 * 2];
    int i, j, off;
    int layer;
    s16 prev, t;

    lbl_803DCF44 = 0;
    if (lbl_803DCF4D != 0 && getHudHiddenFrameCount() == 0)
    {
        lbl_803DCF4D--;
    }
    if ((s8)mapBlockFlag == 1)
    {
        lbl_803DCF4F = 1;
        mapBlockFlag = 0;
        return;
    }
    if ((s8)lbl_803DCF4F == 0)
    {
        return;
    }
    lbl_803DCF4F = 0;
    if (getHudHiddenFrameCount() != 0)
    {
        lbl_803DCF4D = 2;
    }

    for (i = 0; i < 0x47; i++)
    {
        counts[i] = 0;
    }
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;

    for (layer = 0; layer < 5; layer++)
    {
        f32 scale = lbl_803DECE0[0];
        u8* idx = mapGetBlockIdx(layer);
        int gz, gx, base;
        for (gz = 0, base = 0; gz < 0x10; gz++, base += 0x10)
        {
            f32 fz0 = scale * gz;
            u8* p = idx + base;
            for (gx = 0; gx < 0x10; gx++, p++)
            {
                if ((s8) * p >= 0)
                {
                    u8* blk = mapGetBlock((s8) * p);
                    int tn, toff;
                    f32 fx0;
                    tn = 0;
                    toff = 0;
                    fx0 = lbl_803DECE0[0] * gx;
                    for (; tn < *(u16*)(blk + 0x9c); tn++, toff += 0x14)
                    {
                        if (gIntersectLineCount < 0x5dc)
                        {
                            s16* tp = (s16*)(*(int*)(blk + 0x70) + toff);
                            u8* rec = (u8*)(lbl_803DCF34 + gIntersectLineCount * 0x10);
                            f32 fx, fz;
                            u8* rp;
                            int k;
                            rec[0] = *((u8*)tp + 0xc);
                            rec[1] = *((u8*)tp + 0xd);
                            rec[3] = *((u8*)tp + 0xf);
                            if (((s8)rec[3] & 0x3f) == 0x11)
                            {
                                *(s8*)(rec + 3) = rec[3] & ~0x3f;
                                *(s8*)(rec + 3) = rec[3] | 2;
                            }
                            rec[2] = *((u8*)tp + 0xe);
                            *(s8*)(rec + 2) = rec[2] ^ 0x10;
                            *(s16*)(rec + 0xc) = tp[8];
                            fx = fx0 + playerMapOffsetX;
                            fz = fz0 + playerMapOffsetZ;
                            k = 0;
                            rp = rec;
                            for (; k < 2; k++, tp++, rp += 2)
                            {
                                f32 x = fx + tp[0];
                                f32 y = tp[2];
                                f32 z = tp[4] + fz;
                                if (gIntersectPointCount < 0x6a4)
                                {
                                    *(s16*)(rp + 4) = insertPoint(gIntersectLineCount, edges, x, y, z);
                                }
                            }
                            counts[(s8)rec[3] & 0x3f]++;
                            gIntersectLineCount++;
                        }
                    }
                }
            }
        }
    }

    for (i = 0, off = 0; i < gIntersectLineCount; i++, off += 0x10)
    {
        u8* rec = (u8*)(lbl_803DCF34 + off);
        int idx = *(s16*)(rec + 4) * 2;
        s16* e0 = &edges[idx];
        s16* e1;
        s16 v = e0[0];
        if (v > -1 && v != i)
        {
            *(s16*)(rec + 8) = v;
        }
        else
        {
            v = e0[1];
            if (v > -1 && v != i)
            {
                *(s16*)(rec + 8) = v;
            }
            else
            {
                *(s16*)(rec + 8) = -1;
            }
        }
        idx = *(s16*)(rec + 6) * 2;
        e1 = &edges[idx];
        v = e1[0];
        if (v > -1 && v != i)
        {
            *(s16*)(rec + 0xa) = v;
        }
        else
        {
            v = e1[1];
            if (v > -1 && v != i)
            {
                *(s16*)(rec + 0xa) = v;
            }
            else
            {
                *(s16*)(rec + 0xa) = -1;
            }
        }
    }

    if (lbl_803DCF40 != 0)
    {
        int done;
        for (i = 0, off = 0; i < gIntersectLineCount; i++, off += 2)
        {
            *(s16*)(lbl_803DCF40 + off) = i;
        }
        done = 0;
        while (done == 0)
        {
            done = 1;
            for (j = 0, off = 0; j < gIntersectLineCount - 1; j++, off += 2)
            {
                s16* p = (s16*)(lbl_803DCF40 + off);
                s16 a = p[0];
                s16 b;
                int ta = (s8) * (u8*)(lbl_803DCF34 + a * 0x10 + 3) & 0x3f;
                b = p[1];
                if (ta < ((s8) * (u8*)(lbl_803DCF34 + b * 0x10 + 3) & 0x3f))
                {
                    p[0] = b;
                    *(s16*)(lbl_803DCF40 + off + 2) = a;
                    done = 0;
                }
            }
        }
    }

    for (i = 0x46; i != 0; i--)
    {
        counts[i - 1] = counts[i - 1] + counts[i];
    }

    for (i = 0, off = 0; i < gIntersectLineCount; i++, off += 0x10)
    {
        int tt = ((s8) * (u8*)(lbl_803DCF34 + off + 3) & 0x3f) + 1;
        s16 c = counts[tt];
        counts[tt] = c + 1;
        *(s16*)(gIntersectLineIndexTable + c * 2) = i;
    }

    for (i = 0; i < gIntersectLineCount - 1; i++)
    {
    }

    for (i = 0; i < 40; i++)
    {
        ((u16*)gIntersectSegmentTypeTable)[i] = 0xffff;
    }

    prev = -1;
    for (i = 0, off = 0; i < gIntersectLineCount; i++, off += 2)
    {
        t = (s16)((s8) * (u8*)(lbl_803DCF34 + *(s16*)(gIntersectLineIndexTable + off) * 0x10 + 3) & 0x3f);
        if (t >= 0x14)
        {
            t = 1;
            debugPrintf(sTrackIntersectFuncOverflowFormat, 1);
        }
        if (prev != t)
        {
            u16 v = i;
            int ti = t * 2;
            ((u16*)gIntersectSegmentTypeTable)[ti] = v;
            if (prev != -1)
            {
                int pi = prev * 2;
                ((u16*)gIntersectSegmentTypeTable)[pi + 1] = v;
            }
            prev = t;
        }
    }
    if (prev != -1)
    {
        int pi = prev * 2;
        ((u16*)gIntersectSegmentTypeTable)[pi + 1] = gIntersectLineCount;
    }
    lbl_803DCF44 = 1;
}

/* doLotsOfMath -- sweep a 2D segment (with radius) against the intersection
 * line table, sliding/clipping the end point; fills *out with the last hit. */
extern const f32 lbl_803DECCC;
extern const f32 lbl_803DECD0;
extern const f32 lbl_803DECD4;
extern f32 lbl_803DB660;

#pragma optimization_level 2
int doLotsOfMath(void* ptA, void* ptB, int flags, void* out, int* obj,
                 int pmask, int seg, int ytol, int self, f32 radius)
{
    f32* A = ptA;
    s16 hits[6];
    f32 dists[5];
    f32 fracs[5];
    f32 lb[4], la[4], ld[4];
    f32 pos[4];
    s16 m[2];
    int start, end;
    int vt, vp, lineIdx;
    s8 flag1;
    int flag2;
    int flag4;
    f32 minX, maxX, minZ, maxZ;
    int count, found;
    s16* hitp;
    f32 *fracp, *distp;
    int mask;
    int si2, si16;
    int i;
    f32 dist;
    s8 lineType;

    if (obj != NULL)
    {
        if ((s8)seg != -1)
        {
            u8* tbl = *(u8**)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x38);
            start = tbl[(s8)seg * 2];
            end = tbl[(s8)seg * 2 + 1];
        }
        else
        {
            start = 0;
            end = *(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x5c);
        }
        lineIdx = 0;
        vt = *(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x34);
        vp = *(int*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x3c);
        if (((GameObject*)obj)->objectFlags & 0x100)
        {
            end = 0;
        }
    }
    else
    {
        if ((s8)seg != -1)
        {
            u16* segtbl = (u16*)gIntersectSegmentTypeTable;
            start = segtbl[(s8)seg * 2];
            end = segtbl[(s8)seg * 2 + 1];
        }
        else
        {
            start = 0;
            end = gIntersectLineCount;
        }
        lineIdx = gIntersectLineIndexTable;
        vt = lbl_803DCF34;
        vp = (int)lbl_803DCF38;
    }

    flag1 = !(flags & 1);
    flag2 = flags & 2;
    flag4 = flags & 4;

    pos[2] = A[0];
    pos[0] = A[2];
    pos[3] = ((f32*)ptB)[0];
    pos[1] = ((f32*)ptB)[2];
    if (pos[2] < pos[3])
    {
        minX = pos[2];
        maxX = pos[3];
    }
    else
    {
        minX = pos[3];
        maxX = pos[2];
    }
    if (pos[0] < pos[1])
    {
        minZ = pos[0];
        maxZ = pos[1];
    }
    else
    {
        minZ = pos[1];
        maxZ = pos[0];
    }
    minX = minX - radius;
    maxX = maxX + radius;
    minZ = minZ - radius;
    maxZ = maxZ + radius;
    minX = minX - lbl_803DECCC;
    maxX = maxX + lbl_803DECCC;
    minZ = minZ - lbl_803DECCC;
    maxZ = maxZ + lbl_803DECCC;

    count = 0;
    found = 1;
    hitp = hits;
    fracp = fracs;
    distp = dists;
    mask = (s8)pmask;
    si2 = start << 1;
    si16 = start << 4;

    while (found)
    {
        s16* ep;
        u8* rp;
        found = 0;
        ep = (s16*)(lineIdx + si2);
        rp = (u8*)(vt + si16);
        for (i = start; i < end; i++, ep++, rp += 0x10)
        {
            u8* rec;
            int i0, i1;
            f32 *va, *vb;
            f32 ax2, ay2, az2, bx2, by2, bz2;
            f32 ylo, yhi, ha, hb;
            f32 dx, dz, len;
            int mi;

            dist = lbl_803DECD0;
            if (lineIdx != 0)
            {
                rec = (u8*)(vt + ep[0] * 0x10);
            }
            else
            {
                rec = rp;
            }
            if ((mask & ~(s8)rec[2]) == 0) continue;
            if ((s8)rec[3] & 0x40) continue;
            i0 = *(s16*)(rec + 4);
            i1 = *(s16*)(rec + 6);
            if ((s8)rec[3] & 0x80)
            {
                if ((u8)flag4 != 0) continue;
                lineType = 0;
            }
            else
            {
                lineType = 1;
            }
            if (flag2 != 0)
            {
                lineType = 1;
            }
            va = (f32*)(vp + i0 * 0xc);
            ax2 = va[0];
            ay2 = va[1];
            az2 = va[2];
            vb = (f32*)(vp + i1 * 0xc);
            bx2 = vb[0];
            by2 = vb[1];
            bz2 = vb[2];
            if (ax2 < minX && bx2 < minX) continue;
            if (ax2 > maxX && bx2 > maxX) continue;
            if (az2 < minZ && bz2 < minZ) continue;
            if (az2 > maxZ && bz2 > maxZ) continue;

            ylo = ay2;
            if (by2 < ay2) ylo = by2;
            ylo = ylo - (f32)(s8)
            ytol;
            if ((s8)rec[2] & 0x80)
            {
                ha = (f32) * (s16*)rec;
                hb = ha;
            }
            else
            {
                ha = (f32)(s8)
                rec[0];
                hb = (f32)(s8)
                rec[1];
            }
            yhi = ay2 + ha;
            if (by2 + hb > ay2 + ha) yhi = by2 + hb;
            yhi = yhi + (f32)(s8)
            ytol;
            if (A[1] < ylo) continue;
            if (A[1] > yhi) continue;

            dx = bx2 - ax2;
            dz = bz2 - az2;
            if (__AR_Callback == dx * dx + dz * dz) continue;
            len = sqrtf(dx * dx + dz * dz);
            dx = dx / len;
            dz = dz / len;
            lb[0] = dx;
            la[0] = dz;
            ld[0] = -(dx * ax2 + dz * az2);
            lb[1] = -dx;
            la[1] = -dz;
            ld[1] = -(-dx * bx2 + -dz * bz2);
            lb[2] = -dz;
            la[2] = dx;
            {
                f32 q0 = -dz * (lbl_803DECB8 * -dz + ax2);
                f32 q1 = dx * (lbl_803DECB8 * dx + az2);
                ld[2] = -(q0 + q1);
            }
            lb[3] = dz;
            la[3] = -dx;
            {
                f32 q0 = dz * (radius * dz + ax2);
                f32 q1 = -dx * (radius * -dx + az2);
                ld[3] = -(q0 + q1);
            }
            lbl_803DCF54 = lbl_803DECD4 * (dz * radius);
            lbl_803DCF50 = lbl_803DECD4 * (-dx * radius);

            {
                s16* mp = m;
                f32* zp = &pos[0];
                f32* xp = &pos[2];
                for (mi = 0; mi < 2; mi++)
                {
                    s16 mb = 1;
                    f32 pz, px;
                    f32 *ap, *bp, *dp;
                    int n;
                    *mp = 0;
                    pz = zp[0];
                    px = xp[0];
                    ap = la;
                    bp = lb;
                    dp = ld;
                    n = 2;
                    do
                    {
                        if (dp[0] + (px * bp[0] + pz * ap[0]) < __AR_Callback) *mp |= mb;
                        mb = (s16)(mb << 1);
                        if (dp[1] + (px * bp[1] + pz * ap[1]) < __AR_Callback) *mp |= mb;
                        mb = (s16)(mb << 1);
                        ap += 2;
                        bp += 2;
                        dp += 2;
                        n--;
                    }
                    while (n != 0);
                    xp[0] = px;
                    zp[0] = pz;
                    mp++;
                    zp++;
                    xp++;
                }
            }
            {
                s16 mx = m[0] ^ m[1];
                s16 ma = m[0] & m[1];
                dist = lbl_803DECC4;
                if ((m[0] & 0xc) == 0xc)
                {
                    if (m[0] & 1)
                    {
                        found = fn_800630D8(&pos[2], &pos[0], ax2, az2, radius, lineType);
                        dist = __AR_Callback;
                    }
                    else if (m[0] & 2)
                    {
                        found = fn_800630D8(&pos[2], &pos[0], bx2, bz2, radius, lineType);
                        dist = lbl_803DECC4;
                    }
                    else if (lineType != 0)
                    {
                        pos[3] = pos[3] + lbl_803DCF54;
                        pos[1] = pos[1] + lbl_803DCF50;
                    }
                }
                else if (mx & 0xc)
                {
                    if (ma & 1)
                    {
                        found = fn_800630D8(&pos[2], &pos[0], ax2, az2, radius, lineType);
                        dist = __AR_Callback;
                    }
                    else if (ma & 2)
                    {
                        found = fn_800630D8(&pos[2], &pos[0], bx2, bz2, radius, lineType);
                        dist = lbl_803DECC4;
                    }
                    else if (m[0] & 4)
                    {
                        f32 sx = pos[3] - pos[2];
                        f32 sz = pos[1] - pos[0];
                        f32 t0 = ld[3] + (pos[2] * lb[3] + pos[0] * la[3]);
                        f32 t1 = ld[3] + (pos[3] * lb[3] + pos[1] * la[3]);
                        f32 fr, cx, cz;
                        s16 ok;
                        if (t0 != t1)
                        {
                            fr = t0 / (t0 - t1);
                        }
                        else
                        {
                            fr = __AR_Callback;
                        }
                        cx = sx * fr + pos[2];
                        cz = sz * fr + pos[0];
                        lbl_803DCF58 = fr;
                        ok = 1;
                        if (ld[0] + (cx * lb[0] + cz * la[0]) < __AR_Callback)
                        {
                            found = fn_800630D8(&pos[2], &pos[0], ax2, az2, radius, lineType);
                            ok = 0;
                            dist = __AR_Callback;
                        }
                        if (ld[1] + (cx * lb[1] + cz * la[1]) < __AR_Callback)
                        {
                            found = fn_800630D8(&pos[2], &pos[0], bx2, bz2, radius, lineType);
                            ok = 0;
                            dist = lbl_803DECC4;
                        }
                        if (ok != 0)
                        {
                            found = 1;
                            if (lineType != 0)
                            {
                                int j;
                                if (flag1 != 0)
                                {
                                    f32 t3 = ld[3] + (pos[3] * lb[3] + pos[1] * la[3]);
                                    pos[3] = -(t3 * lb[3] - pos[3]);
                                    pos[1] = -(t3 * la[3] - pos[1]);
                                    j = 0;
                                    while (ld[3] + (pos[3] * lb[3] + pos[1] * la[3]) < lbl_803DB660)
                                    {
                                        pos[3] = pos[3] + lbl_803DB660 * lb[3];
                                        pos[1] = pos[1] + lbl_803DB660 * la[3];
                                        j++;
                                        if (j > 0xa)
                                        {
                                            pos[3] = pos[2];
                                            pos[1] = pos[0];
                                            break;
                                        }
                                    }
                                }
                                else
                                {
                                    pos[3] = cx;
                                    pos[1] = cz;
                                    j = 0;
                                    while (ld[3] + (pos[3] * lb[3] + pos[1] * la[3]) < lbl_803DB660)
                                    {
                                        pos[3] = pos[3] + lbl_803DB660 * lb[3];
                                        pos[1] = pos[1] + lbl_803DB660 * la[3];
                                        j++;
                                        if (j > 0xa)
                                        {
                                            pos[3] = pos[2];
                                            pos[1] = pos[0];
                                            break;
                                        }
                                    }
                                }
                                dist = sqrtf((pos[3] - ax2) * (pos[3] - ax2) + (pos[1] - az2) * (pos[1] - az2)) / len;
                            }
                        }
                    }
                }
            }
            if (found) break;
        }
        if (found)
        {
            *hitp = i;
            *fracp = lbl_803DCF58;
            *distp = dist;
            hitp++;
            fracp++;
            distp++;
            count++;
            if (count > 4)
            {
                found = 0;
                if (lineType != 0)
                {
                    pos[3] = pos[2];
                    pos[1] = pos[0];
                }
            }
        }
    }

    if (count != 0 && out != NULL)
    {
        f32* outf = out;
        int pick = count - 1;
        int hi;
        s16* rec2;
        f32 fa, fb;
        f32 *va2, *vb2;
        if (flag1 == 0)
        {
            pick = 0;
        }
        outf[0x11] = fracs[0] * sqrtf((((f32*)ptB)[0] - pos[2]) * (((f32*)ptB)[0] - pos[2])
            + (((f32*)ptB)[2] - pos[0]) * (((f32*)ptB)[2] - pos[0]));
        outf[0x12] = dists[pick];
        hi = hits[pick];
        if (lineIdx != 0)
        {
            rec2 = (s16*)(vt + *(s16*)(lineIdx + hi * 2) * 0x10);
        }
        else
        {
            rec2 = (s16*)(vt + hi * 0x10);
        }
        {
            int j0 = rec2[2];
            int j1 = rec2[3];
            if ((s8) * (u8*)((u8*)rec2 + 2) & 0x80)
            {
                fa = rec2[0];
                fb = fa;
            }
            else
            {
                fa = (f32)(s8) * (u8*)rec2;
                fb = (f32)(s8) * ((u8*)rec2 + 1);
            }
            outf[1] = ((f32*)vp)[j0 * 3];
            va2 = (f32*)(vp + j0 * 0xc);
            outf[3] = va2[1];
            outf[0xf] = outf[3] + fa;
            outf[5] = va2[2];
            outf[2] = ((f32*)vp)[j1 * 3];
            vb2 = (f32*)(vp + j1 * 0xc);
            outf[4] = vb2[1];
            outf[0x10] = outf[4] + fb;
            outf[6] = vb2[2];
            *(s8*)((u8*)out + 0x50) = (s8)(*((u8*)rec2 + 3) & 0x3f);
            *((u8*)out + 0x52) = *((u8*)rec2 + 2);
            *(s8*)((u8*)out + 0x51) = rec2[6];
            *(int**)out = obj;
            *(s16*)((u8*)out + 0x4c) = rec2[4];
            *(s16*)((u8*)out + 0x4e) = rec2[5];
        }
    }
    if (count != 0)
    {
        lbl_803DCF4C++;
        count = 1;
        ((f32*)ptB)[0] = pos[3];
        ((f32*)ptB)[2] = pos[1];
    }
    return count;
}
#pragma optimization_level reset

/* hitDetect_800667ec -- sweep each input sphere against the gathered triangle
 * lists, bouncing/sliding up to 10 times per slot; returns hit mask. */
extern char sTrackHitOverflowError[];
extern void fn_80137948(char* fmt, ...);

u8 hitDetect_800667ec(int mode, void* tri1, void* tri2, int startPos, int endPos, int count, void* slots, int flagsArg)
{
    TrackBlockDescriptor* descBase;
    f32 *ep1, *ep2;
    f32 *sp1, *sp2;
    u8* slotp;
    int slotByte;
    s16 i;
    u8 retLo;
    u8 curBit;
    u8 retHi;
    u8 typeb;
    u8 typeb2;
    TrackBlockDescriptor* descSave;
    u8 type;
    f32 edge2[4];
    f32 edge1[4];
    f32 edge0[4];
    f32 rdata[3];
    f32 evec[3];
    f32 vb[3];
    f32 va[3];
    f32 ws[3];
    f32 we[3];
    f32 delta[3];
    f32 hitpt[3];
    f32 cur[3];
    f32 plane[4];
    f32 norm4[4];
    f32 sv[9];
    f32 dir[3];
    f32 tmp1[3];
    f32 tmp2[3];
    f32 frac;
    TrackBlockDescriptor* descEnd;
    f32 offX, offZ;
    f32 radius, maxStep, negStep;
    f32 mag;
    f32 eps;
    TrackBlockDescriptor* desc;
    u8* tri;
    int objmtx;
    u8 bounces;
    u8 found;
    s16 hit;

    descBase = gTrackBlockDescriptors;
    descEnd = descBase + gActiveTrackBlockCount;
    eps = __AR_Callback;
    offX = (f32) * (int*)gTrackGridOrigin;
    offZ = (f32) * (int*)(gTrackGridOrigin + 8);
    i = 0;
    retLo = 0;
    retHi = 0;
    curBit = 1;
    ep1 = (f32*)endPos;
    ep2 = (f32*)endPos;
    sp1 = (f32*)startPos;
    sp2 = (f32*)startPos;
    slotp = slots;
    for (; i < count; i++)
    {
        cur[0] = ep1[0];
        cur[1] = ep2[1];
        cur[2] = ep2[2];
        sv[6] = sp1[0];
        sv[7] = sp2[1];
        sv[8] = sp2[2];
        radius = *(f32*)(slotp + 0x40);
        slotByte = (int)slots + i;
        type = *(u8*)(slotByte + 0x54);
        maxStep = radius + lbl_803DB660;
        rdata[0] = radius;
        rdata[1] = radius * radius;
        bounces = 0;
        negStep = -maxStep;
        do
        {
            we[0] = cur[0];
            we[1] = cur[1];
            we[2] = cur[2];
            found = 0;
            hit = 0;
            for (desc = descBase; (u32)desc < (u32)descEnd; desc++)
            {
                if (desc->object != NULL)
                {
                    Matrix_TransformPoint(desc->alternateMatrix, sv[6], sv[7], sv[8],
                                          &ws[0], &ws[1], &ws[2]);
                    Matrix_TransformPoint(desc->currentMatrix, cur[0], cur[1], cur[2],
                                          &we[0], &we[1], &we[2]);
                }
                else
                {
                    ws[0] = sv[6] - offX;
                    ws[1] = sv[7];
                    ws[2] = sv[8] - offZ;
                    we[0] = cur[0] - offX;
                    we[1] = cur[1];
                    we[2] = cur[2] - offZ;
                }
                PSVECSubtract(we, ws, delta);
                mag = PSVECMag(delta);
                if (mag > eps)
                {
                    PSVECNormalize(delta, dir);
                }
                for (tri = (u8*)(gTrackTriangleBuffer + desc->firstTriangle * 0x4c);
                     (u32)tri < (u32)(gTrackTriangleBuffer + desc[1].firstTriangle * 0x4c); tri += 0x4c)
                {
                    s16* ts = (s16*)tri;
                    f32 dE, dS;
                    u8 b;
                    tri[0x4b] = 0;
                    if ((s8)tri[0x49] & 0x10) continue;
                    plane[0] = *(f32*)(tri + 4);
                    plane[1] = *(f32*)(tri + 8);
                    plane[2] = *(f32*)(tri + 0xc);
                    plane[3] = *(f32*)tri;
                    dE = (plane[3] + PSVECDotProduct(plane, we)) - radius;
                    if (!(dE <= (*(f32*)&__AR_Callback))) continue;
                    dS = (plane[3] + PSVECDotProduct(plane, ws)) - radius;
                    if ((dS <= (*(f32*)&__AR_Callback) && dE >= (*(f32*)&__AR_Callback)) || (dS >= (*(f32*)&__AR_Callback) && dE <= (*(f32*)&__AR_Callback)))
                    {
                        f32 lo, hi;
                        if (dS != dE)
                        {
                            frac = dS / (dS - dE);
                        }
                        else
                        {
                            frac = (*(f32*)&__AR_Callback);
                        }
                        PSVECScale(delta, hitpt, frac);
                        PSVECAdd(hitpt, ws, hitpt);
                        lo = ts[(*(u8*)(tri + 0x4a) & 0xf) + 0xb] - maxStep;
                        if (hitpt[1] < lo) continue;
                        hi = ts[(*(u8*)(tri + 0x4a) >> 4) + 0xb] + maxStep;
                        if (hitpt[1] > hi) continue;
                        edge0[0] = *(f32*)(tri + 0x24);
                        edge0[1] = *(f32*)(tri + 0x28);
                        edge0[2] = *(f32*)(tri + 0x2c);
                        edge0[3] = -((f32)ts[0xe] * edge0[2] + ((f32)ts[8] * edge0[0] + ts[0xb] * edge0[1]))
                            + PSVECDotProduct(edge0, hitpt);
                        edge1[0] = *(f32*)(tri + 0x30);
                        edge1[1] = *(f32*)(tri + 0x34);
                        edge1[2] = *(f32*)(tri + 0x38);
                        edge1[3] = -((f32)ts[0xf] * edge1[2] + ((f32)ts[9] * edge1[0] + ts[0xc] * edge1[1]))
                            + PSVECDotProduct(edge1, hitpt);
                        edge2[0] = *(f32*)(tri + 0x3c);
                        edge2[1] = *(f32*)(tri + 0x40);
                        edge2[2] = *(f32*)(tri + 0x44);
                        edge2[3] = -((f32)ts[0x10] * edge2[2] + ((f32)ts[0xa] * edge2[0] + ts[0xd] * edge2[1]))
                            + PSVECDotProduct(edge2, hitpt);
                        b = 0;
                        if (radius > (*(f32*)&__AR_Callback))
                        {
                            if (edge0[3] > (*(f32*)&__AR_Callback)) b |= 1;
                            if (edge1[3] > (*(f32*)&__AR_Callback)) b |= 2;
                            if (edge2[3] > (*(f32*)&__AR_Callback)) b |= 4;
                        }
                        if (b == 0)
                        {
                            hit = 1;
                            goto found_hit;
                        }
                        tri[0x4b] = b;
                    }
                    else if (dE >= negStep && radius > (*(f32*)&__AR_Callback))
                    {
                        edge0[0] = *(f32*)(tri + 0x24);
                        edge0[1] = *(f32*)(tri + 0x28);
                        edge0[2] = *(f32*)(tri + 0x2c);
                        edge0[3] = -((f32)ts[0xe] * edge0[2] + ((f32)ts[8] * edge0[0] + ts[0xb] * edge0[1]))
                            + PSVECDotProduct(edge0, ws);
                        edge1[0] = *(f32*)(tri + 0x30);
                        edge1[1] = *(f32*)(tri + 0x34);
                        edge1[2] = *(f32*)(tri + 0x38);
                        edge1[3] = -((f32)ts[0xf] * edge1[2] + ((f32)ts[9] * edge1[0] + ts[0xc] * edge1[1]))
                            + PSVECDotProduct(edge1, ws);
                        edge2[0] = *(f32*)(tri + 0x3c);
                        edge2[1] = *(f32*)(tri + 0x40);
                        edge2[2] = *(f32*)(tri + 0x44);
                        edge2[3] = -((f32)ts[0x10] * edge2[2] + ((f32)ts[0xa] * edge2[0] + ts[0xd] * edge2[1]))
                            + PSVECDotProduct(edge2, ws);
                        b = 0;
                        if (edge0[3] > (*(f32*)&__AR_Callback)) b |= 1;
                        if (edge1[3] > (*(f32*)&__AR_Callback)) b |= 2;
                        if (edge2[3] > (*(f32*)&__AR_Callback)) b |= 4;
                        tri[0x4b] = b;
                    }
                }
                if ((*(f32*)&__AR_Callback) == mag) goto found_hit;
                for (tri = (u8*)(gTrackTriangleBuffer + desc->firstTriangle * 0x4c);
                     (u32)tri < (u32)(gTrackTriangleBuffer + desc[1].firstTriangle * 0x4c); tri += 0x4c)
                {
                    u8 bit;
                    if (tri[0x4b] == 0) continue;
                    for (bit = 0; bit < 3; bit++)
                    {
                        s16* vs;
                        u8 k;
                        if ((tri[0x4b] & (1 << bit)) == 0) continue;
                        k = bit + 1;
                        if (k > 2) k = 0;
                        vs = (s16*)(tri + bit * 2);
                        va[0] = vs[8];
                        va[1] = vs[0xb];
                        va[2] = vs[0xe];
                        vs = (s16*)(tri + k * 2);
                        vb[0] = vs[8];
                        vb[1] = vs[0xb];
                        vb[2] = vs[0xe];
                        PSVECSubtract(vb, va, evec);
                        rdata[2] = Vec3_Normalize(evec);
                        if (hitDetectFn_800664fc(va, ws, dir, mag, maxStep, (*(f32*)&__AR_Callback), hitpt, plane, &frac))
                        {
                            hit = 1;
                            goto found_hit;
                        }
                    }
                }
                for (tri = (u8*)(gTrackTriangleBuffer + desc->firstTriangle * 0x4c);
                     (u32)tri < (u32)(gTrackTriangleBuffer + desc[1].firstTriangle * 0x4c); tri += 0x4c)
                {
                    u8 bit;
                    if (tri[0x4b] == 0) continue;
                    for (bit = 0; bit < 3; bit++)
                    {
                        s16* vs;
                        u8 k;
                        int ok;
                        f32 dotv, sq, disc, root, tt, rr, rr2;
                        if ((tri[0x4b] & (1 << bit)) == 0) continue;
                        k = bit + 1;
                        if (k > 2) k = 0;
                        vs = (s16*)(tri + bit * 2);
                        va[0] = vs[8];
                        va[1] = vs[0xb];
                        va[2] = vs[0xe];
                        rr = *(volatile f32*)&rdata[1];
                        PSVECSubtract(va, ws, tmp1);
                        dotv = PSVECDotProduct(tmp1, dir);
                        sq = PSVECSquareMag(tmp1);
                        if (dotv < (*(f32*)&__AR_Callback) && sq > rr)
                        {
                            ok = 0;
                        }
                        else
                        {
                            disc = -(dotv * dotv - sq);
                            if (disc > rr)
                            {
                                ok = 0;
                            }
                            else
                            {
                                root = sqrtf(rr - disc);
                                if (sq > rr)
                                {
                                    dotv = dotv - root;
                                }
                                else
                                {
                                    dotv = dotv + root;
                                }
                                if (dotv >= (*(f32*)&__AR_Callback) && dotv <= mag)
                                {
                                    PSVECScale(dir, hitpt, dotv);
                                    PSVECAdd(ws, hitpt, hitpt);
                                    PSVECSubtract(hitpt, va, plane);
                                    PSVECNormalize(plane, plane);
                                    root = sqrtf(rr);
                                    plane[3] = -PSVECDotProduct(hitpt, plane) + root;
                                    frac = dotv;
                                    ok = 1;
                                }
                                else
                                {
                                    ok = 0;
                                }
                            }
                        }
                        if (ok)
                        {
                            hit = 1;
                            goto found_hit;
                        }
                        vs = (s16*)(tri + k * 2);
                        vb[0] = vs[8];
                        vb[1] = vs[0xb];
                        vb[2] = vs[0xe];
                        rr2 = radius * radius;
                        PSVECSubtract(vb, ws, tmp2);
                        sq = PSVECDotProduct(tmp2, dir);
                        dotv = PSVECSquareMag(tmp2);
                        if (sq < (*(f32*)&__AR_Callback) && dotv > rr2)
                        {
                            ok = 0;
                        }
                        else
                        {
                            disc = -(sq * sq - dotv);
                            if (disc > rr2)
                            {
                                ok = 0;
                            }
                            else
                            {
                                root = sqrtf(rr2 - disc);
                                if (dotv > rr2)
                                {
                                    sq = sq - root;
                                }
                                else
                                {
                                    sq = sq + root;
                                }
                                if (sq >= (*(f32*)&__AR_Callback) && sq <= mag)
                                {
                                    PSVECScale(dir, hitpt, sq);
                                    PSVECAdd(ws, hitpt, hitpt);
                                    PSVECSubtract(hitpt, vb, plane);
                                    PSVECNormalize(plane, plane);
                                    root = sqrtf(rr2);
                                    plane[3] = -PSVECDotProduct(hitpt, plane) + root;
                                    frac = sq;
                                    ok = 1;
                                }
                                else
                                {
                                    ok = 0;
                                }
                            }
                        }
                        if (ok)
                        {
                            hit = 1;
                            goto found_hit;
                        }
                    }
                }
            found_hit:
                if (hit != 0)
                {
                    we[0] = hitpt[0];
                    we[1] = hitpt[1];
                    we[2] = hitpt[2];
                    norm4[0] = plane[0];
                    norm4[1] = plane[1];
                    norm4[2] = plane[2];
                    norm4[3] = plane[3];
                    typeb = tri[0x48];
                    typeb2 = tri[0x49];
                    objmtx = *(int*)desc;
                    sv[0] = ws[0];
                    sv[1] = ws[1];
                    sv[2] = ws[2];
                    sv[3] = hitpt[0];
                    sv[4] = hitpt[1];
                    sv[5] = hitpt[2];
                    descSave = desc;
                    found = 1;
                    if (type == 7)
                    {
                        f32* out4 = (f32*)((u8*)slots + i * 0x10);
                        out4[0] = norm4[0];
                        out4[1] = norm4[1];
                        out4[2] = norm4[2];
                        out4[3] = norm4[3];
                        *(u8*)(slotByte + 0x50) = typeb;
                        *(u8*)(slotByte + 0x58) = typeb2;
                        *(int*)(slotp + 0x5c) = objmtx;
                        bounces++;
                        goto slot_done;
                    }
                    break;
                }
            }
            if (found != 0)
            {
                bounces++;
                if (bounces > 10)
                {
                    fn_80137948(sTrackHitOverflowError);
                    cur[0] = sv[6];
                    cur[1] = sv[7];
                    cur[2] = sv[8];
                    found = 0;
                }
                else
                {
                    f32* out4;
                    f32 pen;
                    if (objmtx != 0)
                    {
                        Matrix_TransformPoint(descSave->currentMatrix, cur[0], cur[1], cur[2],
                                              &cur[0], &cur[1], &cur[2]);
                    }
                    else
                    {
                        cur[0] = cur[0] - offX;
                        cur[2] = cur[2] - offZ;
                    }
                    pen = (norm4[3] + (cur[2] * norm4[2] + (cur[0] * norm4[0] + cur[1] * norm4[1]))) - radius;
                    fn_800660C8(sv, cur, &sv[3], norm4, type, pen, maxStep);
                    if (objmtx != 0)
                    {
                        Matrix_TransformPoint(descSave->currentCollisionMatrix, cur[0], cur[1], cur[2],
                                              &cur[0], &cur[1], &cur[2]);
                    }
                    else
                    {
                        cur[0] = cur[0] + offX;
                        cur[2] = cur[2] + offZ;
                    }
                    out4 = (f32*)((u8*)slots + i * 0x10);
                    out4[0] = norm4[0];
                    out4[1] = norm4[1];
                    out4[2] = norm4[2];
                    out4[3] = norm4[3];
                    *(u8*)(slotByte + 0x50) = typeb;
                    *(u8*)(slotByte + 0x58) = typeb2;
                    *(int*)(slotp + 0x5c) = objmtx;
                }
            }
        }
        while (found != 0);
    slot_done:
        if (bounces != 0)
        {
            if (norm4[1] >= __AR_Size || norm4[1] <= lbl_803DECEC)
            {
                retHi = retHi | curBit;
            }
            ep1[0] = cur[0];
            ep2[1] = cur[1];
            ep2[2] = cur[2];
            *(s16*)((u8*)slots + 0x6c) = *(s16*)((u8*)slots + 0x6c) + 1;
            retLo = retLo | curBit;
        }
        curBit = (u8)(curBit << 1);
        slotp += 4;
        ep1 += 3;
        ep2 += 3;
        sp1 += 3;
        sp2 += 3;
    }
    return (u8)(retLo | (retHi << 4));
}
