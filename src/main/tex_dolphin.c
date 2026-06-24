#include "main/tex_dolphin.h"
#include "main/game_object.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"
#include "main/model_light.h"
#include "main/pi_dolphin.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
extern f32 modelLightStruct_getRadius(void* light);
extern void modelLightStruct_getPosition(void* light, void* a, void* b, void* c);
extern void modelLightStruct_selectBrightestAabbLights(f32 x1, f32 y1, f32 z1, f32 x2, f32 y2, f32 z2, u8* dest,
                                                       int count, int* out);
extern int Shader_getLayer();
extern void selectTexture();
extern void fn_8004CE0C();
extern void fn_8004DA54();
extern void fn_8004E0FC();
extern void renderHeavyFog();
extern void fn_8004EECC();
extern void fn_8004EF9C();
extern void fn_8004F080();
extern void fn_8004F2B0();
extern void fn_8004F380();
extern void fn_8004F6D8();
extern void fn_8004FA30();
extern void fn_8004FDA0();
extern void fn_80051528();
extern void fn_80051868();
extern void fn_80051B00();
extern void textureFn_800524ec();
extern int textureCrazyPointerFollowFn_80054c30();
extern void fn_8005D3B4();
extern void textureFn_8006c4e0();
extern void fn_80088730();
extern void objGetColor(int slot, u8* red, u8* green, u8* blue);
extern BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx);

extern f32 lbl_803DEBC8;
extern f32 lbl_803DEBCC;
extern f32 displayOffsetH_803DEBFC;
extern f32 CurrTiming_803DEC20;
extern f32 gTexIndMtxScale;
extern f32 FBSet_803DEC28;
extern f32 lbl_803DEC2C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DEBB0;
extern int gTexDimmedLightList;
extern int gTexBlockLightList;
extern int lbl_803DCE30;
extern int* lbl_803DCE34;
extern int lbl_803DCE68;
extern int lbl_803DCE6C;

typedef struct TexOverride
{
    int id;
    int ptr;
    int unk8;
    s16 count;
    u8 layerByte;
    u8 padF;
} TexOverride;

extern int gTexIndMtxTable;
extern u8 lbl_8037E0C0[];
extern u8 lbl_803DB638;
extern int gTexShaderAmbColor;
extern int gTexLightmapAmbColor;
extern s8 gTexIndMtxScaleExp;
extern int lbl_80382008[5];
extern FrustumPlane gViewFrustumPlanes[5];
extern int gTexShaderFogColor;
extern int gTexLightmapFogColor;

u8 mapBlockBounds_HasCornerPastDepthThreshold(int bounds, float* xform)
{
    float v[3];
    u32 i;
    f32 fbset;
    f32 timing;

    i = 0;
    timing = CurrTiming_803DEC20;
    fbset = FBSet_803DEC28;
    while (1)
    {
        {
            switch (i)
            {
            case 0:
                v[0] = (f32) * (s16*)(bounds + 0x6);
                v[1] = (f32) * (s16*)(bounds + 0x8);
                v[2] = (f32) * (s16*)(bounds + 0xa);
                break;
            case 1:
                v[0] = (f32) * (s16*)(bounds + 0xc);
                v[1] = (f32) * (s16*)(bounds + 0x8);
                v[2] = (f32) * (s16*)(bounds + 0xa);
                break;
            case 2:
                v[0] = (f32) * (s16*)(bounds + 0x6);
                v[1] = (f32) * (s16*)(bounds + 0xe);
                v[2] = (f32) * (s16*)(bounds + 0xa);
                break;
            case 3:
                v[0] = (f32) * (s16*)(bounds + 0xc);
                v[1] = (f32) * (s16*)(bounds + 0xe);
                v[2] = (f32) * (s16*)(bounds + 0xa);
                break;
            case 4:
                v[0] = (f32) * (s16*)(bounds + 0x6);
                v[1] = (f32) * (s16*)(bounds + 0x8);
                v[2] = (f32) * (s16*)(bounds + 0x10);
                break;
            case 5:
                v[0] = (f32) * (s16*)(bounds + 0xc);
                v[1] = (f32) * (s16*)(bounds + 0x8);
                v[2] = (f32) * (s16*)(bounds + 0x10);
                break;
            case 6:
                v[0] = (f32) * (s16*)(bounds + 0x6);
                v[1] = (f32) * (s16*)(bounds + 0xe);
                v[2] = (f32) * (s16*)(bounds + 0x10);
                break;
            case 7:
                v[0] = (f32) * (s16*)(bounds + 0xc);
                v[1] = (f32) * (s16*)(bounds + 0xe);
                v[2] = (f32) * (s16*)(bounds + 0x10);
                break;
            }
        }
        v[0] = v[0] * timing;
        v[1] = v[1] * timing;
        v[2] = v[2] * timing;
        PSMTXMultVec((const float (*)[4])xform, (Vec*)v, (Vec*)v);
        if (v[2] >= fbset)
        {
            return 1;
        }
        i = i + 1;
        if ((int)i < 8)
        {
            continue;
        }
        return 0;
    }
}

typedef struct IndMtxCopy
{
    int w[6];
} IndMtxCopy;

void mapBlockRender_drawLightmapIndirectPasses(int blockData, u8* arg2, int* bitReader, Mtx viewMtx)
{
    Mtx m2;
    float m[2][3];
    int lb;
    int la;
    int ptr;
    int bptr;
    int pos;
    u32 word;
    u32 flags;
    u8 count;
    int i;
    f32 k24;
    f32 kH;
    f32 k;
    u8* tbl;

    pos = bitReader[4];
    word = ((u8*)*bitReader)[pos >> 3];
    bptr = *bitReader + (pos >> 3);
    word = word | (u32)(*(u8*)(bptr + 1) << 8);
    word = word | (u32)(*(u8*)(bptr + 2) << 16);
    bitReader[4] = pos + 8;
    ptr = *(int*)(blockData + 0x68) + ((word >> (pos & 7)) & 0xff) * 0x1c;
    flags = *(u32*)(arg2 + 0x3c);
    if ((flags & 0x4000) != 0)
    {
        count = 4;
    }
    else if ((flags & 0x8000) != 0)
    {
        count = 8;
    }
    else if ((flags & 0x10000) != 0)
    {
        count = 0x10;
    }
    else
    {
        return;
    }
    i = 0;
    k = lbl_803DEC2C;
    tbl = (u8*)&gTexIndMtxTable;
    for (; i < count; i = i + 1)
    {
        k24 = gTexIndMtxScale;
        kH = displayOffsetH_803DEBFC;
        PSMTXTrans(m2, lbl_803DEBCC, k * (f32)(i + 1), lbl_803DEBCC);
        PSMTXConcat(viewMtx, m2, m2);
        GXLoadPosMtxImm(m2, 0);
        *(IndMtxCopy*)m = *(IndMtxCopy*)tbl;
        textureFn_8006c4e0(&la, &lb);
        selectTexture(*(int*)(la + (u8)i * 4), 1);
        m[0][0] = (f32)((i & 0xff) + 1) * k24 * kH;
        m[1][1] = m[0][0];
        GXSetIndTexMtx(1, (const float (*)[3])m, gTexIndMtxScaleExp);
        GXCallDisplayList(*(void**)ptr, (u32) * (u16*)(ptr + 4));
    }
}

int mapBlockRender_setLightmapShader(int blockData, int* bitReader, int* outPtr)
{
    int shader;
    u32 shaderIdx;
    volatile int colorWord;
    int _base;
    u32 _bits;
    u32 bitPos;
    u8 colR;
    u8 colG;
    u8 colB;

    colorWord = gTexLightmapFogColor;
    bitPos = bitReader[4];
    {
        int _off = (int)bitPos >> 3;
        _base = *bitReader;
        _bits = *(u8*)(_base + _off);
        _base += _off;
        _bits |= (u32) * (u8*)(_base + 1) << 8;
        _bits |= (u32) * (u8*)(_base + 2) << 16;
        bitReader[4] = bitPos + 6;
        shaderIdx = (_bits >> (bitPos & 7)) & 0x3f;
        shader = *(int*)(blockData + 0x64) + shaderIdx * 0x44;
    }
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    selectTexture(*(int*)Shader_getLayer(shader, 0), 0);
    if ((*(u32*)(shader + 0x3c) & 4) != 0)
    {
        _gxSetFogParams();
        goto LAB_8005E630;
    }
    GXSetFog(0, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, *(GXColor*)&colorWord);
LAB_8005E630:
    if ((*(u32*)(shader + 0x3c) & 1) == 0)
    {
        if ((*(u32*)(shader + 0x3c) & 0x40000) == 0)
        {
            if ((*(u32*)(shader + 0x3c) & 0x800) == 0)
            {
                if ((*(u32*)(shader + 0x3c) & 0x1000) == 0) goto LAB_8005E6D0;
            }
        }
    }
    GXSetChanAmbColor(0, *(GXColor*)&gTexLightmapAmbColor);
    if ((*(u32*)(shader + 0x3c) & 0x40000) != 0)
    {
        GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
        goto LAB_8005E718;
    }
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    goto LAB_8005E718;
LAB_8005E6D0:
    objGetColor(0, &colB, &colG, &colR);
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(0, *(GXColor*)&colB);
LAB_8005E718:
    return shader;
}

void mapBlockRender_drawDimmedAabbLights(u32 bounds, u32 blockXform, int i)
{
    int* lightPtr;
    f32 posZ;
    f32 posY;
    f32 posX;
    int lightCount;
    u8 colorA;
    u8 colorB;
    u8 colorG;
    u8 colorR;

    {
        f32 fz = playerMapOffsetZ;
        f32 fldZ = *(float*)((int)blockXform + 0x38);
        f32 fldY = *(float*)((int)blockXform + 0x28);
        f32 fx = playerMapOffsetX;
        f32 fldX = *(float*)((int)blockXform + 0x18);
        f32 ax0 = (f32)(*(short*)((int)bounds + 6) >> 3) + fldX;
        f32 az0 = (f32)(*(short*)((int)bounds + 10) >> 3) + fldZ;
        f32 ax1 = (f32)(*(short*)((int)bounds + 0xc) >> 3) + fldX;
        f32 az1 = (f32)(*(short*)((int)bounds + 0x10) >> 3) + fldZ;
        modelLightStruct_selectBrightestAabbLights(
            ax0 + fx,
            (f32)(*(short*)((int)bounds + 8) >> 3) + fldY,
            az0 + fz,
            ax1 + fx,
            (f32)(*(short*)((int)bounds + 0xe) >> 3) + fldY,
            az1 + fz,
            (u8*)&gTexDimmedLightList, 2, &lightCount);
    }
    resetLotsOfRenderVars();
    fn_8004CE0C(i);
    i = 0;
    lightPtr = &gTexDimmedLightList;
    {
        u8* pColorA = &colorA;
        u8* pColorB = &colorB;
        u8* pColorG = &colorG;
        f32* pPosZ = &posZ;
        f32* pPosY = &posY;
        for (; i < lightCount; lightPtr = lightPtr + 1, i = i + 1)
        {
            modelLightStruct_getDiffuseColor((void*)*lightPtr, &colorR, pColorG, pColorB, pColorA);
            colorR = ((int)colorR >> 1) + ((int)colorR >> 2);
            colorG = ((int)colorG >> 1) + ((int)colorG >> 2);
            colorB = ((int)colorB >> 1) + ((int)colorB >> 2);
            modelLightStruct_getPosition((void*)*lightPtr, &posX, pPosY, pPosZ);
            modelLightStruct_getRadius((void*)*lightPtr);
            fn_8004FA30(&colorR, &posX);
        }
    }
    textureFn_800528bc();
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_BACK);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return;
}

u32
frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ,
                                f32 maxZ, f32* planeOffsets)
{
    FrustumPlane* plane;
    int cornerIndex;
    int i;
    float nearX;
    float nearY;
    float nearZ;
    float farX;
    float farY;
    float farZ;

    plane = gViewFrustumPlanes;
    for (i = 0; i < 5; i++)
    {
        cornerIndex = plane[i].aabbCornerIndex;
        if ((cornerIndex & 1) != 0)
        {
            nearX = maxX;
            farX = minX;
        }
        else
        {
            nearX = minX;
            farX = maxX;
        }
        if ((cornerIndex & 2) != 0)
        {
            nearY = maxY;
            farY = minY;
        }
        else
        {
            nearY = minY;
            farY = maxY;
        }
        if ((cornerIndex & 4) != 0)
        {
            nearZ = maxZ;
            farZ = minZ;
        }
        else
        {
            nearZ = minZ;
            farZ = maxZ;
        }
        if ((nearX * plane[i].normalX + nearY * plane[i].normalY + nearZ * plane[i].normalZ + plane[i].distance + planeOffsets[i]
                < lbl_803DEBCC) &&
            (farX * plane[i].normalX + farY * plane[i].normalY + farZ * plane[i].normalZ + plane[i].distance + planeOffsets[i] <
                lbl_803DEBCC))
            return 0;
    }
    return 1;
}

u8
mapBlockBounds_ComputeAndTestPlanes(int bounds, int block, FrustumPlane* planes, int planeCount, f32* minX,
                                    f32* minY, f32* minZ, f32* maxX, f32* maxY, f32* maxZ)
{
    u8 cornerIndex;
    float nearX;
    float nearY;
    float nearZ;
    float farX;
    float farY;
    float farZ;
    int i;

    *maxX = (f32)(*(short*)(bounds + 0xc) >> 3) + *(float*)(block + 0x18);
    *minX = (f32)(*(short*)(bounds + 6) >> 3) + *(float*)(block + 0x18);
    *maxY = (f32)(*(short*)(bounds + 0xe) >> 3) + *(float*)(block + 0x28);
    *minY = (f32)(*(short*)(bounds + 8) >> 3) + *(float*)(block + 0x28);
    *maxZ = (f32)(*(short*)(bounds + 0x10) >> 3) + *(float*)(block + 0x38);
    *minZ = (f32)(*(short*)(bounds + 10) >> 3) + *(float*)(block + 0x38);
    for (i = 0; i < planeCount; i = i + 1)
    {
        cornerIndex = planes->aabbCornerIndex;
        if ((cornerIndex & 1) != 0)
        {
            nearX = *maxX;
            farX = *minX;
        }
        else
        {
            nearX = *minX;
            farX = *maxX;
        }
        if ((cornerIndex & 2) != 0)
        {
            nearY = *maxY;
            farY = *minY;
        }
        else
        {
            nearY = *minY;
            farY = *maxY;
        }
        if ((cornerIndex & 4) != 0)
        {
            nearZ = *maxZ;
            farZ = *minZ;
        }
        else
        {
            nearZ = *minZ;
            farZ = *maxZ;
        }
        if ((planes->distance + (nearX * planes->normalX + nearY * planes->normalY + nearZ * planes->normalZ) <
                lbl_803DEBCC)
            && (planes->distance + (farX * planes->normalX + farY * planes->normalY + farZ * planes->normalZ) <
                lbl_803DEBCC))
        {
            return 0;
        }
        planes++;
    }
    return 1;
}

#pragma opt_propagation off
void mapBlockRender_callList(u32 hi, u32 lo, int block, u8* obj, int* stream, float* mtx)
{
    u8 dBig[16];
    int dOut[3];
    int count;
    float x1;
    float y1;
    float z1;
    float x2;
    float y2;
    float z2;
    u8 c[4];
    u8 g[4];
    int* p;
    int i;
    u32 vis;
    u32 flags;
    u32 word;
    int pos;
    int bptr;
    u8* base;
    int ptr;

    base = lbl_8037E0C0;
    pos = stream[4];
    word = ((u8*)*stream)[pos >> 3];
    bptr = *stream + (pos >> 3);
    word = word | (u32)(*(u8*)(bptr + 1) << 8);
    word = word | (u32)(*(u8*)(bptr + 2) << 16);
    stream[4] = pos + 8;
    ptr = *(int*)(block + 0x68) + ((word >> (pos & 7)) & 0xff) * 0x1c;
    if ((obj != NULL) && ((*(u32*)(obj + 0x3c) & 2) != 0))
    {
        goto end;
    }
    if (mapBlockBounds_ComputeAndTestPlanes(ptr, block, (FrustumPlane*)(base + 0x987c), 5, &x1, &y1, &z1, &x2, &y2, &z2)
        == 0)
    {
        goto end;
    }
    if ((u8)hi == 0)
    {
        flags = *(u32*)(obj + 0x3c);
        if ((flags & 0x80000000) != 0)
        {
            fn_8005D3B4(ptr, block, *(u8*)(ptr + 0x18));
            {
                int* row = (int*)(base + lbl_803DCE30 * 16);
                *(int*)((char*)row + 0xc) = 5;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
        else if (((flags & 0x40000000) != 0) || ((flags & 0x2000) != 0))
        {
            fn_8005D3B4(ptr, block, *(u8*)(ptr + 0x18));
            {
                int* row = (int*)(base + lbl_803DCE30 * 16);
                *(int*)((char*)row + 0xc) = 4;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
    }
    else
    {
        if (obj != NULL)
        {
            flags = *(u32*)(obj + 0x3c);
            if (((flags & 0x80000000) == 0) && ((flags & 0x20000) == 0))
            {
                if ((obj != NULL) && ((flags & 0x80000) != 0))
                {
                    count = 0;
                }
                else
                {
                    modelLightStruct_selectBrightestAabbLights(x1 + playerMapOffsetX, y1,
                                                               z1 + playerMapOffsetZ, x2 + playerMapOffsetX, y2,
                                                               z2 + playerMapOffsetZ,
                                                               (u8*)&gTexBlockLightList, 2, &count);
                }
                if ((obj != NULL) &&
                    (((*(u32*)(obj + 0x3c) & 0x800) != 0 || ((*(u32*)(obj + 0x3c) & 0x1000) != 0))))
                {
                    fn_80088730(g);
                    g[3] = 0;
                    g[2] = 0;
                    g[1] = 0;
                    g[0] = 0;
                    if (count == 0)
                    {
                        if ((obj != NULL) && ((*(u32*)(obj + 0x3c) & 0x800) != 0))
                        {
                            fn_8004EF9C(g);
                        }
                        else
                        {
                            fn_8004EECC(g);
                        }
                    }
                    else
                    {
                        modelLightStruct_getDiffuseColor((void*)gTexBlockLightList, &c[0], &c[1], &c[2], &c[3]);
                        modelLightStruct_getPosition((void*)gTexBlockLightList, &dOut[0], &dOut[1], &dOut[2]);
                        modelLightStruct_getRadius((void*)gTexBlockLightList);
                        fn_8004F6D8(c, &dOut[0], g);
                        p = &gTexBlockLightList + 1;
                        for (i = 1; i < count; i = i + 1)
                        {
                            modelLightStruct_getDiffuseColor((void*)*p, &c[0], &c[1], &c[2], &c[3]);
                            modelLightStruct_getPosition((void*)*p, &dOut[0], &dOut[1], &dOut[2]);
                            modelLightStruct_getRadius((void*)*p);
                            fn_8004F380(c, &dOut[0]);
                            p = p + 1;
                        }
                        if ((obj != NULL) && ((*(u32*)(obj + 0x3c) & 0x800) != 0))
                        {
                            fn_8004F2B0();
                        }
                        else
                        {
                            fn_8004F080();
                        }
                    }
                }
                else
                {
                    p = &gTexBlockLightList;
                    for (i = 0; i < count; i = i + 1)
                    {
                        modelLightStruct_getDiffuseColor((void*)*p, &c[0], &c[1], &c[2], &c[3]);
                        modelLightStruct_getPosition((void*)*p, &dOut[0], &dOut[1], &dOut[2]);
                        modelLightStruct_getRadius((void*)*p);
                        fn_8004FA30(c, &dOut[0]);
                        p = p + 1;
                    }
                }
                if ((obj != NULL) && ((*(u32*)(obj + 0x3c) & 0x2000) != 0))
                {
                    if ((obj != NULL) && ((*(u32*)(obj + 0x3c) & 0x40000000) != 0))
                    {
                        vis = lo;
                    }
                    else
                    {
                        u8 res2 = mapBlockBounds_ComputeAndTestPlanes(ptr, block, (FrustumPlane*)(base + 0x9818), 5,
                                                                      &x1, &y1, &z1, &x2, &y2, &z2);
                        if (((res2 == 0) || ((u8)lo == 0)) && ((res2 != 0) || ((u8)lo != 0)))
                        {
                            vis = 0;
                        }
                        else
                        {
                            vis = 1;
                        }
                        if ((u8)lo != 0)
                        {
                            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                            gxSetZMode_(1, 3, 0);
                            gxSetPeControl_ZCompLoc_(1);
                            GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                        }
                    }
                    if ((u8)vis == 0)
                    {
                        goto end;
                    }
                    fn_8004D230();
                }
                textureFn_800528bc();
            }
        }
        GXCallDisplayList(*(void**)ptr, *(u16*)(ptr + 4));
        flags = *(u32*)(obj + 0x3c);
        if ((((flags & 0x4000) != 0) || ((flags & 0x8000) != 0) || ((flags & 0x10000) != 0)) &&
            (mapBlockBounds_HasCornerPastDepthThreshold(ptr, mtx) != 0))
        {
            fn_8005D3B4(ptr, block, 0x17);
            {
                int* row = (int*)(base + lbl_803DCE30 * 16);
                *(int*)((char*)row + 0xc) = 6;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
    }
end:
    return;
}
#pragma opt_propagation reset

void mapBlockRender_setupShaderTextures(int shader, int mode)
{
    int layerIdx;
    int* layer;
    int texId;
    float* texMtx;
    int* ovr;
    int overrideIdx;
    int remain;
    u8 layerByte;
    TexOverride* pE;
    u32 colorWord;
    Mtx texMatrix;

    colorWord = lbl_803DEBB0;
    if ((*(u8*)(shader + 0x41) == 2) &&
        (texId = Shader_getLayer(shader, 1), (*(u8*)(texId + 4) & 0x7f) == 9u))
    {
        layer = (int*)Shader_getLayer(shader, 0);
        layerByte = *(u8*)((int)layer + 5);
        if (layerByte != '\0')
        {
            int texVal = *layer;
            TexOverride* base;
            overrideIdx = 0;
            base = (TexOverride*)lbl_803DCE6C;
            pE = base;
            for (remain = 0x50; remain != 0; remain--)
            {
                if (((0 < pE->count) && ((u32)pE->id == texVal)) &&
                    ((int)layerByte == pE->layerByte))
                {
                    texId = textureCrazyPointerFollowFn_80054c30(texVal, base[overrideIdx].ptr);
                    goto layer0_done;
                }
                pE = pE + 1;
                overrideIdx = overrideIdx + 1;
            }
            texId = texVal;
        }
        else
        {
            texId = *layer;
        }
    layer0_done:
        if (*(u8*)((int)layer + 6) != 0xff)
        {
            layerIdx = (u32) * (u8*)((int)layer + 6) * 0x10;
            PSMTXTrans(texMatrix,
                       *(float*)(lbl_803DCE68 + layerIdx) / lbl_803DEBC8,
                       *(float*)(lbl_803DCE68 + layerIdx + 4) / lbl_803DEBC8,
                       lbl_803DEBCC);
            texMtx = (float*)texMatrix;
        }
        else
        {
            texMtx = (float*)0x0;
        }
        fn_80051B00(texId, texMtx, 0, &colorWord);
        if ((*(u32*)(shader + 0x3c) & 0x100) != 0)
        {
            fn_8004D928();
        }
        layer = (int*)Shader_getLayer(shader, 1);
        layerByte = *(u8*)((int)layer + 5);
        if (layerByte != '\0')
        {
            int texVal = *layer;
            TexOverride* base;
            overrideIdx = 0;
            base = (TexOverride*)lbl_803DCE6C;
            pE = base;
            for (remain = 0x50; remain != 0; remain--)
            {
                if (((0 < pE->count) && ((u32)pE->id == texVal)) &&
                    ((int)layerByte == pE->layerByte))
                {
                    texId = textureCrazyPointerFollowFn_80054c30(texVal, base[overrideIdx].ptr);
                    goto layer1_done;
                }
                pE = pE + 1;
                overrideIdx = overrideIdx + 1;
            }
            texId = texVal;
        }
        else
        {
            texId = *layer;
        }
    layer1_done:
        if (*(u8*)((int)layer + 6) != 0xff)
        {
            layerIdx = (u32) * (u8*)((int)layer + 6) * 0x10;
            PSMTXTrans(texMatrix,
                       *(float*)(lbl_803DCE68 + layerIdx) / lbl_803DEBC8,
                       *(float*)(lbl_803DCE68 + layerIdx + 4) / lbl_803DEBC8,
                       lbl_803DEBCC);
            texMtx = (float*)texMatrix;
        }
        else
        {
            texMtx = (float*)0x0;
        }
        fn_80051868(texId, texMtx, 9);
        textureFn_800524ec((char*)&colorWord);
    }
    else
    {
        for (layerIdx = 0; layerIdx < (int)(u32) * (u8*)(shader + 0x41); layerIdx = layerIdx + 1)
        {
            layer = (int*)Shader_getLayer(shader, layerIdx);
            if (*(void**)layer != NULL)
            {
                int texVal = *layer;
                layerByte = *(u8*)((int)layer + 5);
                if (layerByte != '\0')
                {
                    overrideIdx = 0;
                    ovr = (int*)lbl_803DCE6C;
                    for (remain = 0x50; remain != 0; remain--)
                    {
                        if (((0 < *(short*)(ovr + 3)) && ((u32)*ovr == texVal)) &&
                            ((int)layerByte == (int)*(u8*)((int)ovr + 0xe)))
                        {
                            texId = textureCrazyPointerFollowFn_80054c30(texVal, ((int*)lbl_803DCE6C)[overrideIdx * 4 + 1]);
                            goto layerN_done;
                        }
                        ovr = ovr + 4;
                        overrideIdx = overrideIdx + 1;
                    }
                }
                texId = texVal;
            layerN_done:
                if (*(u8*)((int)layer + 6) != 0xff)
                {
                    int mtxOff = (u32) * (u8*)((int)layer + 6) * 0x10;
                    PSMTXTrans(texMatrix,
                               *(float*)(lbl_803DCE68 + mtxOff) / lbl_803DEBC8,
                               *(float*)(lbl_803DCE68 + mtxOff + 4) / lbl_803DEBC8,
                               lbl_803DEBCC);
                    texMtx = (float*)texMatrix;
                }
                else
                {
                    texMtx = (float*)0x0;
                }
                layerByte = *(u8*)(layer + 1) & 0x7f;
                if ((*(u32*)(shader + 0x3c) & 0x40000) != 0)
                {
                    fn_80051528(texId, texMtx);
                }
                else
                {
                    fn_80051868(texId, texMtx, layerByte);
                }
            }
            else
            {
                gxColorFn_800523d0();
            }
        }
        if ((*(u32*)(shader + 0x3c) & 0x100) != 0)
        {
            fn_8004D928();
        }
    }
    return;
}

int mapBlockRender_setShader(u8 doSetup, int blockData, int* bitReader)
{
    u32 shader;
    u32 shaderIdx;
    int fogColorWord;
    u8 ambB;
    u8 ambG;
    u8 ambR;
    u8 fogRgba[4];
    int _base;
    u32 _bits;
    u32 uPos;

    fogColorWord = gTexShaderFogColor;
    uPos = bitReader[4];
    {
        int _off = (int)uPos >> 3;
        _base = *bitReader;
        _bits = *(u8*)(_base + _off);
        _base += _off;
        _bits |= (u32) * (u8*)(_base + 1) << 8;
        _bits |= (u32) * (u8*)(_base + 2) << 16;
        bitReader[4] = uPos + 6;
        shaderIdx = (_bits >> (uPos & 7)) & 0x3f;
        shader = *(int*)(blockData + 0x64) + shaderIdx * 0x44;
    }

    if (doSetup == 0)
    {
        return shader;
    }

    if ((*(u32*)(shader + 0x3c) & 4) != 0)
    {
        _gxSetFogParams();
        goto LAB_8005F608;
    }
    GXSetFog(0, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, *(GXColor*)&fogColorWord);
LAB_8005F608:
    if ((shader != 0) && ((*(u32*)(shader + 0x3c) & 0x80000000) != 0))
    {
        return shader;
    }
    if ((shader != 0) && ((*(u32*)(shader + 0x3c) & 0x20000) != 0))
    {
        u32 res;
        res = AttractMovie_DrawTextureCallback(0, 0, 0);
        if ((res & 0xff) != 0)
        {
            return shader;
        }
    }
    resetLotsOfRenderVars();
    if ((*(u32*)(shader + 0x3c) & 0x80) != 0)
    {
        fn_8004DA54(shader);
        goto LAB_8005F690;
    }
    mapBlockRender_setupShaderTextures(shader, 0x80);
LAB_8005F690:
    if ((*(u32*)(shader + 0x3c) & 0x20) != 0)
    {
        int* lPtr = lbl_803DCE34;
        if (lPtr != 0)
        {
            fn_8004FDA0(lPtr, &lbl_80382008, &lbl_803DB638);
            goto LAB_8005F6F4;
        }
    }
    if ((*(u32*)(shader + 0x3c) & 0x40) != 0)
    {
        fn_8004E0FC();
        goto LAB_8005F6F4;
    }
    if (isHeavyFogEnabled())
    {
        getColor803dd01c(fogRgba);
        renderHeavyFog(fogRgba);
    }
LAB_8005F6F4:
    if (((*(u32*)(shader + 0x3c) & 0x40000000) != 0) || ((*(u32*)(shader + 0x3c) & 0x20000000) != 0))
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, 3, 0);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        goto LAB_8005F7FC;
    }
    if ((*(u32*)(shader + 0x3c) & 0x400) != 0)
    {
        if ((*(u32*)(shader + 0x3c) & 0x80) == 0)
        {
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
            gxSetZMode_(1, 3, 1);
            gxSetPeControl_ZCompLoc_(0);
            GXSetAlphaCompare(GX_GREATER, 0, GX_AOP_AND, GX_GREATER, 0);
            goto LAB_8005F7FC;
        }
    }
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    gxSetZMode_(1, 3, 1);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
LAB_8005F7FC:
    if ((*(u32*)(shader + 0x3c) & 1) == 0)
    {
        if ((*(u32*)(shader + 0x3c) & 0x40000) == 0)
        {
            if ((*(u32*)(shader + 0x3c) & 0x800) == 0)
            {
                if ((*(u32*)(shader + 0x3c) & 0x1000) == 0) goto LAB_8005F89C;
            }
        }
    }
    GXSetChanAmbColor(0, *(GXColor*)&gTexShaderAmbColor);
    if ((*(u32*)(shader + 0x3c) & 0x40000) != 0)
    {
        GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
        goto LAB_8005F8E4;
    }
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    goto LAB_8005F8E4;
LAB_8005F89C:
    objGetColor(0, &ambR, &ambG, &ambB);
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, 0, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(0, *(GXColor*)&ambR);
LAB_8005F8E4:
    if ((*(u32*)(shader + 0x3c) & 0x8) != 0)
    {
        GXSetCullMode(GX_CULL_BACK);
        goto LAB_8005F908;
    }
    GXSetCullMode(GX_CULL_NONE);
LAB_8005F908:
    return shader;
}
