#include "main/tex_dolphin.h"
#include "main/game_object.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"
#include "main/model_light.h"
#include "main/pi_dolphin.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
#define GX_FOG_NONE 0
#define GX_LEQUAL 3
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
extern const f32 displayOffsetH_803DEBFC;
extern f32 CurrTiming_803DEC20;
extern const f32 gTexIndMtxScale;
extern f32 FBSet_803DEC28;
extern const f32 lbl_803DEC2C;
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

/*
 * MapBlockBoundsRec - a 0x1c per-block render record (block->unk68 array,
 * stride 0x1c). Offset 0 is the GX display-list pointer, offset 4 its u16
 * byte-size; offsets 6..0x10 are the s16 AABB (min/max X,Y,Z in 1/8 units);
 * offset 0x18 is an u8 selector. Pad covers unobserved ranges.
 */
typedef struct MapBlockBoundsRec
{
    void* dlist;
    u16 dlistSize;
    s16 minX;
    s16 minY;
    s16 minZ;
    s16 maxX;
    s16 maxY;
    s16 maxZ;
    u8 pad12[0x18 - 0x12];
    u8 selector;
    u8 pad19[0x1C - 0x19];
} MapBlockBoundsRec;

/*
 * TexShadowRow - 0x10-stride rows of the pending-shadow queue at the head of
 * lbl_8037E0C0 (indexed by lbl_803DCE30, bumped after each fn_8005D3B4 push).
 * mapBlockRender_callList writes type (4/5 = object shadow, 6 = indirect
 * lightmap) through a byte-offset launder off &row->type - the launder is
 * load-bearing (#112: keeps the field offset as a store displacement).
 */
typedef struct TexShadowRow
{
    int unk0;
    int unk4;
    int unk8;
    int type;
} TexShadowRow;

extern int gTexIndMtxTable[];
extern u8 lbl_8037E0C0[];
extern u8 lbl_803DB638;
extern int gTexShaderAmbColor;
extern int gTexLightmapAmbColor;
extern s8 gTexIndMtxScaleExp;
extern int lbl_80382008[5];
#define FRUSTUM_PLANE_COUNT 5
extern FrustumPlane gViewFrustumPlanes[FRUSTUM_PLANE_COUNT];
extern int gTexShaderFogColor;
extern int gTexLightmapFogColor;

u8 mapBlockBounds_HasCornerPastDepthThreshold(int bounds, float* xform)
{
    MapBlockBoundsRec* b = (MapBlockBoundsRec*)bounds;
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
                v[0] = (f32)b->minX;
                v[1] = (f32)b->minY;
                v[2] = (f32)b->minZ;
                break;
            case 1:
                v[0] = (f32)b->maxX;
                v[1] = (f32)b->minY;
                v[2] = (f32)b->minZ;
                break;
            case 2:
                v[0] = (f32)b->minX;
                v[1] = (f32)b->maxY;
                v[2] = (f32)b->minZ;
                break;
            case 3:
                v[0] = (f32)b->maxX;
                v[1] = (f32)b->maxY;
                v[2] = (f32)b->minZ;
                break;
            case 4:
                v[0] = (f32)b->minX;
                v[1] = (f32)b->minY;
                v[2] = (f32)b->maxZ;
                break;
            case 5:
                v[0] = (f32)b->maxX;
                v[1] = (f32)b->minY;
                v[2] = (f32)b->maxZ;
                break;
            case 6:
                v[0] = (f32)b->minX;
                v[1] = (f32)b->maxY;
                v[2] = (f32)b->maxZ;
                break;
            case 7:
                v[0] = (f32)b->maxX;
                v[1] = (f32)b->maxY;
                v[2] = (f32)b->maxZ;
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

/*
 * MapShader - a 0x44-stride shader record (block->unk64 array). Only the
 * fields this file touches are named: a u32 render-flag word at 0x3c and a
 * u8 layer count at 0x41. The record is otherwise opaque (queried via
 * Shader_getLayer); pad covers unobserved bytes.
 */
typedef struct MapShader
{
    u8 pad0[0x3C - 0x0];
    u32 flags;
    u8 pad40[0x41 - 0x40];
    u8 layerCount;
    u8 pad42[0x44 - 0x42];
} MapShader;
#define SHADER_FLAGS(s) (((MapShader*)(s))->flags)

/*
 * TexLayer - a shader texture layer (returned by Shader_getLayer). Offset 0
 * is the texture id, 4 a u8 type/blend byte (low 7 bits select the blend
 * mode), 5 a u8 texture-override-table selector, 6 a u8 texture-matrix index
 * (0xff = none).
 */
typedef struct TexLayer
{
    int texId;
    u8 typeBits;
    u8 overrideByte;
    u8 mtxIndex;
    u8 pad7;
} TexLayer;

/* NOTE: this fn and mapBlockRender_setLightmapShader sit BEFORE the
 * BitStreamReader/MapBlockData typedefs (declared further down) - a typedef
 * declared any earlier renumbers MWCC's internal @NNN constant-pool symbol
 * for setLightmapShader's 0.0f (a byte diff in the .o strtab). They keep the
 * raw int* bit-cursor spelling ([0]=byte base, [4]=bit position). */
void mapBlockRender_drawLightmapIndirectPasses(int blockData, u8* shader, int* bitReader, Mtx viewMtx)
{
    Mtx passMtx;
    float indMtx[2][3];
    int texTableB;
    int texTable;
    u8 passCount;
    int rec;
    int byteBase;
    u32 bits;
    int bitPos;
    u32 flags;
    u8* mtxSrc;
    int i;

    bitPos = bitReader[4];
    {
        int off = bitPos >> 3;
        byteBase = *bitReader;
        bits = *(u8*)(byteBase + off);
        byteBase += off;
        bits = bits | (u32)(*(u8*)(byteBase + 1) << 8);
        bits = bits | (u32)(*(u8*)(byteBase + 2) << 16);
    }
    bitReader[4] = bitPos + 8;
    /* extract this cursor's 8-bit field (LSB-first: shift out the bits already
     * consumed within the byte, then mask the width) -> bounds-record index */
    rec = (int)((MapBlockBoundsRec*)*(int*)(blockData + 0x68) + ((bits >> (bitPos & 7)) & 0xff));
    flags = SHADER_FLAGS(shader);
    if ((flags & 0x4000) != 0)
    {
        passCount = 4;
    }
    else if ((flags & 0x8000) != 0)
    {
        passCount = 8;
    }
    else if ((flags & 0x10000) != 0)
    {
        passCount = 0x10;
    }
    else
    {
        return;
    }
    i = 0;
    for (; i < passCount; i = i + 1)
    {
        PSMTXTrans(passMtx, lbl_803DEBCC, lbl_803DEC2C * (f32)(i + 1), lbl_803DEBCC);
        PSMTXConcat(viewMtx, passMtx, passMtx);
        GXLoadPosMtxImm(passMtx, GX_PNMTX0);
        mtxSrc = (u8*)gTexIndMtxTable;
        *(IndMtxCopy*)indMtx = *(IndMtxCopy*)mtxSrc;
        textureFn_8006c4e0(&texTable, &texTableB);
        selectTexture(*(int*)(texTable + (u8)i * 4), 1);
        {
            f32 s = (f32)((i & 0xff) + 1) * gTexIndMtxScale;
            indMtx[0][0] = s * displayOffsetH_803DEBFC;
        }
        indMtx[1][1] = indMtx[0][0];
        GXSetIndTexMtx(GX_ITM_0, (const float (*)[3])indMtx, gTexIndMtxScaleExp);
        GXCallDisplayList(((MapBlockBoundsRec*)rec)->dlist, (u32)((MapBlockBoundsRec*)rec)->dlistSize);
    }
}

int mapBlockRender_setLightmapShader(int blockData, int* bitReader, int* outPtr)
{
    int shader;
    u32 shaderIdx;
    int fogColor;
    int byteBase;
    u32 bits;
    u32 bitPos;
    u8 ambColor[3];

    fogColor = gTexLightmapFogColor;
    bitPos = bitReader[4];
    {
        int off = (int)bitPos >> 3;
        byteBase = *bitReader;
        bits = *(u8*)(byteBase + off);
        byteBase += off;
        bits |= (u32) * (u8*)(byteBase + 1) << 8;
        bits |= (u32) * (u8*)(byteBase + 2) << 16;
        bitReader[4] = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = (int)((MapShader*)*(int*)(blockData + 0x64) + shaderIdx);
    }
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    selectTexture(*(int*)Shader_getLayer(shader, 0), 0);
    if ((SHADER_FLAGS(shader) & 4) != 0)
    {
        _gxSetFogParams();
        goto LAB_8005E630;
    }
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, *(GXColor*)&fogColor);
LAB_8005E630:
    if ((SHADER_FLAGS(shader) & 1) == 0)
    {
        if ((SHADER_FLAGS(shader) & 0x40000) == 0)
        {
            if ((SHADER_FLAGS(shader) & 0x800) == 0)
            {
                if ((SHADER_FLAGS(shader) & 0x1000) == 0) goto LAB_8005E6D0;
            }
        }
    }
    GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&gTexLightmapAmbColor);
    if ((SHADER_FLAGS(shader) & 0x40000) != 0)
    {
        GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        goto LAB_8005E718;
    }
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    goto LAB_8005E718;
LAB_8005E6D0:
    objGetColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
LAB_8005E718:
    return shader;
}

/*
 * MapBlockData - the per-map-block record handed to the mapBlockRender_*
 * family as a raw int. Only the two array bases this file reads are named:
 * the 0x44-stride MapShader table at 0x64 and the 0x1c-stride
 * MapBlockBoundsRec table at 0x68. Declared HERE (not at top of file)
 * because any typedef parsed before mapBlockRender_setLightmapShader
 * renumbers MWCC's internal @NNN constant-pool symbol (strtab byte diff).
 */
typedef struct MapBlockData
{
    u8 pad0[0x64];
    MapShader* shaders;        /* 0x64 */
    MapBlockBoundsRec* bounds; /* 0x68 */
} MapBlockData;

/*
 * BitStreamReader - the render-command bit cursor threaded through the
 * mapBlockRender_* family as int*. data points at the packed command bytes;
 * bitPos is the read cursor in bits. Each read grabs a 24-bit little-endian
 * window at byte bitPos>>3 and shifts by bitPos&7. Same mid-file placement
 * constraint as MapBlockData above.
 */
typedef struct BitStreamReader
{
    u8* data;   /* 0x00 */
    int unk4;
    int unk8;
    int unkC;
    int bitPos; /* 0x10 */
} BitStreamReader;

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
        MapBlockBoundsRec* b = (MapBlockBoundsRec*)bounds;
        f32 fz = *(f32*)&playerMapOffsetZ;
        f32 fldZ = *(float*)((int)blockXform + 0x38);
        f32 fldY = *(float*)((int)blockXform + 0x28);
        f32 fx = *(f32*)&playerMapOffsetX;
        f32 fldX = *(float*)((int)blockXform + 0x18);
        f32 ax0 = (f32)(b->minX >> 3) + fldX;
        f32 az0 = (f32)(b->minZ >> 3) + fldZ;
        f32 ax1 = (f32)(b->maxX >> 3) + fldX;
        f32 az1 = (f32)(b->maxZ >> 3) + fldZ;
        modelLightStruct_selectBrightestAabbLights(
            ax0 + fx,
            (f32)(b->minY >> 3) + fldY,
            az0 + fz,
            ax1 + fx,
            (f32)(b->maxY >> 3) + fldY,
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
    gxSetZMode_(1, GX_LEQUAL, 0);
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
    for (i = 0; i < FRUSTUM_PLANE_COUNT; i++)
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
    MapBlockBoundsRec* b = (MapBlockBoundsRec*)bounds;

    *maxX = (f32)(b->maxX >> 3) + *(float*)(block + 0x18);
    *minX = (f32)(b->minX >> 3) + *(float*)(block + 0x18);
    *maxY = (f32)(b->maxY >> 3) + *(float*)(block + 0x28);
    *minY = (f32)(b->minY >> 3) + *(float*)(block + 0x28);
    *maxZ = (f32)(b->maxZ >> 3) + *(float*)(block + 0x38);
    *minZ = (f32)(b->minZ >> 3) + *(float*)(block + 0x38);
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

void mapBlockRender_callList(u32 passSelect, u32 visArg, int block, u8* shader, int* stream, float* mtx)
{
    int lightPos[3];
    int count;
    float minX;
    float minY;
    float minZ;
    float maxX;
    float maxY;
    float maxZ;
    u8 lightColor[4];
    u8 chanColor[4];
    int i;
    u32 visible;
    u32 flags;
    u32 bits;
    int bitPos;
    int byteBase;

    {
    u8* texGlobals;
    int rec;

    texGlobals = lbl_8037E0C0;
    bitPos = ((BitStreamReader*)stream)->bitPos;
    {
        int off = bitPos >> 3;
        byteBase = (int)((BitStreamReader*)stream)->data;
        bits = *(u8*)(byteBase + off);
        byteBase += off;
        bits = bits | (u32)(*(u8*)(byteBase + 1) << 8);
        bits = bits | (u32)(*(u8*)(byteBase + 2) << 16);
    }
    ((BitStreamReader*)stream)->bitPos = bitPos + 8;
    rec = (int)&((MapBlockData*)block)->bounds[(bits >> (bitPos & 7)) & 0xff];
    if ((shader != NULL) && ((SHADER_FLAGS(shader) & 2) != 0))
    {
        goto end;
    }
    if (mapBlockBounds_ComputeAndTestPlanes(rec, block, (FrustumPlane*)(texGlobals + 0x987c), FRUSTUM_PLANE_COUNT, &minX, &minY, &minZ, &maxX, &maxY, &maxZ)
        == 0)
    {
        goto end;
    }
    if ((u8)passSelect == 0)
    {
        flags = SHADER_FLAGS(shader);
        if ((flags & 0x80000000) != 0)
        {
            fn_8005D3B4(rec, block, ((MapBlockBoundsRec*)rec)->selector);
            {
                int shadowType = 5;
                *(int*)((u8*)&((TexShadowRow*)texGlobals)->type + lbl_803DCE30 * sizeof(TexShadowRow)) = shadowType;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
        else if (((flags & 0x40000000) != 0) || ((flags & 0x2000) != 0))
        {
            fn_8005D3B4(rec, block, ((MapBlockBoundsRec*)rec)->selector);
            {
                int shadowType = 4;
                *(int*)((u8*)&((TexShadowRow*)texGlobals)->type + lbl_803DCE30 * sizeof(TexShadowRow)) = shadowType;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
    }
    else
    {
        if (shader != NULL)
        {
            flags = SHADER_FLAGS(shader);
            if (((flags & 0x80000000) == 0) && ((flags & 0x20000) == 0))
            {
                if ((shader != NULL) && ((flags & 0x80000) != 0))
                {
                    count = 0;
                }
                else
                {
                    modelLightStruct_selectBrightestAabbLights(minX + playerMapOffsetX, minY,
                                                               minZ + playerMapOffsetZ, maxX + playerMapOffsetX, maxY,
                                                               maxZ + playerMapOffsetZ,
                                                               (u8*)&gTexBlockLightList, 2, &count);
                }
                if ((shader != NULL) &&
                    (((SHADER_FLAGS(shader) & 0x800) != 0 || ((SHADER_FLAGS(shader) & 0x1000) != 0))))
                {
                    fn_80088730(chanColor);
                    chanColor[3] = 0;
                    chanColor[2] = 0;
                    chanColor[1] = 0;
                    chanColor[0] = 0;
                    if (count == 0)
                    {
                        if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0))
                        {
                            fn_8004EF9C(chanColor);
                        }
                        else
                        {
                            fn_8004EECC(chanColor);
                        }
                    }
                    else
                    {
                        modelLightStruct_getDiffuseColor((void*)gTexBlockLightList, &lightColor[0], &lightColor[1], &lightColor[2], &lightColor[3]);
                        modelLightStruct_getPosition((void*)gTexBlockLightList, &lightPos[0], &lightPos[1], &lightPos[2]);
                        modelLightStruct_getRadius((void*)gTexBlockLightList);
                        fn_8004F6D8(lightColor, &lightPos[0], chanColor);
                        for (i = 1; i < count; i = i + 1)
                        {
                            modelLightStruct_getDiffuseColor((void*)(&gTexBlockLightList)[i], &lightColor[0], &lightColor[1], &lightColor[2], &lightColor[3]);
                            modelLightStruct_getPosition((void*)(&gTexBlockLightList)[i], &lightPos[0], &lightPos[1], &lightPos[2]);
                            modelLightStruct_getRadius((void*)(&gTexBlockLightList)[i]);
                            fn_8004F380(lightColor, &lightPos[0]);
                        }
                        if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0))
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
                    for (i = 0; i < count; i = i + 1)
                    {
                        modelLightStruct_getDiffuseColor((void*)(&gTexBlockLightList)[i], &lightColor[0], &lightColor[1], &lightColor[2], &lightColor[3]);
                        modelLightStruct_getPosition((void*)(&gTexBlockLightList)[i], &lightPos[0], &lightPos[1], &lightPos[2]);
                        modelLightStruct_getRadius((void*)(&gTexBlockLightList)[i]);
                        fn_8004FA30(lightColor, &lightPos[0]);
                    }
                }
                if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x2000) != 0))
                {
                    if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x40000000) != 0))
                    {
                        visible = visArg;
                    }
                    else
                    {
                        u8 mirrorVisible = mapBlockBounds_ComputeAndTestPlanes(rec, block, (FrustumPlane*)(texGlobals + 0x9818), FRUSTUM_PLANE_COUNT,
                                                                      &minX, &minY, &minZ, &maxX, &maxY, &maxZ);
                        if ((mirrorVisible != 0 && (u8)visArg != 0) || (mirrorVisible == 0 && (u8)visArg == 0))
                        {
                            visible = 1;
                        }
                        else
                        {
                            visible = 0;
                        }
                        if ((u8)visArg != 0)
                        {
                            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                            gxSetZMode_(1, GX_LEQUAL, 0);
                            gxSetPeControl_ZCompLoc_(1);
                            GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                        }
                    }
                    if ((u8)visible == 0)
                    {
                        goto end;
                    }
                    fn_8004D230();
                }
                textureFn_800528bc();
            }
        }
        GXCallDisplayList(((MapBlockBoundsRec*)rec)->dlist, ((MapBlockBoundsRec*)rec)->dlistSize);
        flags = SHADER_FLAGS(shader);
        if ((((flags & 0x4000) != 0) || ((flags & 0x8000) != 0) || ((flags & 0x10000) != 0)) &&
            (mapBlockBounds_HasCornerPastDepthThreshold(rec, mtx) != 0))
        {
            fn_8005D3B4(rec, block, 0x17);
            {
                int shadowType = 6;
                *(int*)((u8*)&((TexShadowRow*)texGlobals)->type + lbl_803DCE30 * sizeof(TexShadowRow)) = shadowType;
            }
            lbl_803DCE30 = lbl_803DCE30 + 1;
        }
    }
end:
    return;
    }
}

void mapBlockRender_setupShaderTextures(int shader, int mode)
{
    int layerIdx;
    int* layer;
    int texId;
    float* texMtx;
    int overrideIdx;
    int remain;
    TexOverride* ovr;
    u8 layerByte;
    u32 kColor;
    Mtx texMatrix;

    kColor = lbl_803DEBB0;
    if ((((MapShader*)shader)->layerCount == 2) &&
        (texId = Shader_getLayer(shader, 1), (((TexLayer*)texId)->typeBits & 0x7f) == 9u))
    {
        layer = (int*)Shader_getLayer(shader, 0);
        {
            u8 ovrByte;
            if ((ovrByte = ((TexLayer*)layer)->overrideByte) != '\0')
            {
                int layerTexId = *layer;
                TexOverride* base;
                overrideIdx = 0;
                base = (TexOverride*)lbl_803DCE6C;
                ovr = base;
                for (remain = 0x50; remain != 0; remain--)
                {
                    if (((0 < ovr->count) && ((u32)ovr->id == layerTexId)) &&
                        ((int)ovrByte == ovr->layerByte))
                    {
                        texId = textureCrazyPointerFollowFn_80054c30(layerTexId, base[overrideIdx].ptr);
                        goto layer0_done;
                    }
                    ovr = ovr + 1;
                    overrideIdx = overrideIdx + 1;
                }
                texId = layerTexId;
            }
            else
            {
                texId = *layer;
            }
        }
    layer0_done:
        if (((TexLayer*)layer)->mtxIndex != 0xff)
        {
            ((void (*)(f32, f32*, f32, f32))PSMTXTrans)(
                *(float*)(lbl_803DCE68 + ((u32)((TexLayer*)layer)->mtxIndex << 4)) / lbl_803DEBC8,
                (f32*)texMatrix,
                *(float*)((lbl_803DCE68 + 4) + ((u32)((TexLayer*)layer)->mtxIndex << 4)) / lbl_803DEBC8,
                lbl_803DEBCC);
            texMtx = (float*)texMatrix;
        }
        else
        {
            texMtx = (float*)0x0;
        }
        fn_80051B00(texId, texMtx, 0, &kColor);
        if ((SHADER_FLAGS(shader) & 0x100) != 0)
        {
            fn_8004D928();
        }
        layer = (int*)Shader_getLayer(shader, 1);
        {
            u8 ovrByte;
            if ((ovrByte = ((TexLayer*)layer)->overrideByte) != '\0')
            {
                int layerTexId = *layer;
                TexOverride* base;
                overrideIdx = 0;
                base = (TexOverride*)lbl_803DCE6C;
                ovr = base;
                for (remain = 0x50; remain != 0; remain--)
                {
                    if (((0 < ovr->count) && ((u32)ovr->id == layerTexId)) &&
                        ((int)ovrByte == ovr->layerByte))
                    {
                        texId = textureCrazyPointerFollowFn_80054c30(layerTexId, base[overrideIdx].ptr);
                        goto layer1_done;
                    }
                    ovr = ovr + 1;
                    overrideIdx = overrideIdx + 1;
                }
                texId = layerTexId;
            }
            else
            {
                texId = *layer;
            }
        }
    layer1_done:
        if (((TexLayer*)layer)->mtxIndex != 0xff)
        {
            ((void (*)(f32, f32*, f32, f32))PSMTXTrans)(
                *(float*)(lbl_803DCE68 + ((u32)((TexLayer*)layer)->mtxIndex << 4)) / lbl_803DEBC8,
                (f32*)texMatrix,
                *(float*)((lbl_803DCE68 + 4) + ((u32)((TexLayer*)layer)->mtxIndex << 4)) / lbl_803DEBC8,
                lbl_803DEBCC);
            texMtx = (float*)texMatrix;
        }
        else
        {
            texMtx = (float*)0x0;
        }
        fn_80051868(texId, texMtx, 9);
        textureFn_800524ec((char*)&kColor);
    }
    else
    {
        for (layerIdx = 0; layerIdx < (int)(u32)((MapShader*)shader)->layerCount; layerIdx = layerIdx + 1)
        {
            int layerTexId;
            layer = (int*)Shader_getLayer(shader, layerIdx);
            layerTexId = *layer;
            if ((u32)layerTexId != 0)
            {
                u8 ovrLayerByte;
                {
                    if ((ovrLayerByte = ((TexLayer*)layer)->overrideByte) != '\0')
                    {
                        TexOverride* base;
                        overrideIdx = 0;
                        base = (TexOverride*)lbl_803DCE6C;
                        ovr = base;
                        for (remain = 0x50; remain != 0; remain--)
                        {
                            if (((0 < ovr->count) && ((u32)ovr->id == layerTexId)) &&
                                ((int)ovrLayerByte == ovr->layerByte))
                            {
                                texId = textureCrazyPointerFollowFn_80054c30(layerTexId, base[overrideIdx].ptr);
                                goto layerN_done;
                            }
                            ovr = ovr + 1;
                            overrideIdx = overrideIdx + 1;
                        }
                        texId = layerTexId;
                    }
                    else
                    {
                        texId = layerTexId;
                    }
                layerN_done:
                    if (((TexLayer*)layer)->mtxIndex != 0xff)
                    {
                        float* mvec;
                        int mtxOff = (u32)((TexLayer*)layer)->mtxIndex * 0x10;
                        mvec = (float*)(lbl_803DCE68 + mtxOff);
                        ((void (*)(f32, f32*, f32, f32))PSMTXTrans)(
                            mvec[0] / lbl_803DEBC8, (f32*)texMatrix,
                            mvec[1] / lbl_803DEBC8, lbl_803DEBCC);
                        texMtx = (float*)texMatrix;
                    }
                    else
                    {
                        texMtx = (float*)0x0;
                    }
                    layerByte = ((TexLayer*)layer)->typeBits & 0x7f;
                    if ((SHADER_FLAGS(shader) & 0x40000) != 0)
                    {
                        fn_80051528(texId, texMtx);
                    }
                    else
                    {
                        fn_80051868(texId, texMtx, layerByte);
                    }
                }
            }
            else
            {
                gxColorFn_800523d0();
            }
        }
        if ((SHADER_FLAGS(shader) & 0x100) != 0)
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
    int byteBase;
    int fogColor;
    u8 ambColor[3];
    u8 fogRgba[4];
    u32 bits;
    u32 bitPos;

    fogColor = gTexShaderFogColor;
    bitPos = ((BitStreamReader*)bitReader)->bitPos;
    {
        int off = (int)bitPos >> 3;
        byteBase = (int)((BitStreamReader*)bitReader)->data;
        bits = *(u8*)(byteBase + off);
        byteBase += off;
        bits |= (u32) * (u8*)(byteBase + 1) << 8;
        bits |= (u32) * (u8*)(byteBase + 2) << 16;
        ((BitStreamReader*)bitReader)->bitPos = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = (int)&((MapBlockData*)blockData)->shaders[shaderIdx];
    }

    if (doSetup == 0)
    {
        return shader;
    }

    if ((SHADER_FLAGS(shader) & 4) != 0)
    {
        _gxSetFogParams();
        goto LAB_8005F608;
    }
    GXSetFog(GX_FOG_NONE, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, lbl_803DEBCC, *(GXColor*)&fogColor);
LAB_8005F608:
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x80000000) != 0))
    {
        return shader;
    }
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x20000) != 0))
    {
        u32 res;
        res = AttractMovie_DrawTextureCallback(0, 0, 0);
        if ((res & 0xff) != 0)
        {
            return shader;
        }
    }
    resetLotsOfRenderVars();
    if ((SHADER_FLAGS(shader) & 0x80) != 0)
    {
        fn_8004DA54(shader);
        goto LAB_8005F690;
    }
    mapBlockRender_setupShaderTextures(shader, 0x80);
LAB_8005F690:
    if ((SHADER_FLAGS(shader) & 0x20) != 0)
    {
        int* lightList = lbl_803DCE34;
        if (lightList != 0)
        {
            fn_8004FDA0(lightList, &lbl_80382008, &lbl_803DB638);
            goto LAB_8005F6F4;
        }
    }
    if ((SHADER_FLAGS(shader) & 0x40) != 0)
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
    if (((SHADER_FLAGS(shader) & 0x40000000) != 0) || ((SHADER_FLAGS(shader) & 0x20000000) != 0))
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        goto LAB_8005F7FC;
    }
    if ((SHADER_FLAGS(shader) & 0x400) != 0)
    {
        if ((SHADER_FLAGS(shader) & 0x80) == 0)
        {
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
            gxSetZMode_(1, GX_LEQUAL, 1);
            gxSetPeControl_ZCompLoc_(0);
            GXSetAlphaCompare(GX_GREATER, 0, GX_AOP_AND, GX_GREATER, 0);
            goto LAB_8005F7FC;
        }
    }
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    gxSetZMode_(1, GX_LEQUAL, 1);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
LAB_8005F7FC:
    if ((SHADER_FLAGS(shader) & 1) == 0)
    {
        if ((SHADER_FLAGS(shader) & 0x40000) == 0)
        {
            if ((SHADER_FLAGS(shader) & 0x800) == 0)
            {
                if ((SHADER_FLAGS(shader) & 0x1000) == 0) goto LAB_8005F89C;
            }
        }
    }
    GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&gTexShaderAmbColor);
    if ((SHADER_FLAGS(shader) & 0x40000) != 0)
    {
        GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        goto LAB_8005F8E4;
    }
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    goto LAB_8005F8E4;
LAB_8005F89C:
    objGetColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
    GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
LAB_8005F8E4:
    if ((SHADER_FLAGS(shader) & 0x8) != 0)
    {
        GXSetCullMode(GX_CULL_BACK);
        goto LAB_8005F908;
    }
    GXSetCullMode(GX_CULL_NONE);
LAB_8005F908:
    return shader;
}
