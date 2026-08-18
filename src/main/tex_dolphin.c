#define OBJHITS_STATE_INDEX_S8
#define TEX_SETSHADER_U8
#include "main/map_block.h"
#include "main/texture.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frustum.h"
#include "main/asset_load.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/model_render_instrs_api.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#undef OBJHITS_STATE_INDEX_S8
#include "main/objtype.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSFastCast.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/sky_state.h"
#include "main/track_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/pi_dolphin_api.h"
#include "dolphin/mtx/vec.h"
#define TRACK_BBOX_FLAGS_S8
#define TRACK_BBOX_MASK_TYPE s8
#define TRACK_BBOX_ARG10_TYPE s8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_ARG10_TYPE
#undef TRACK_BBOX_MASK_TYPE
#undef TRACK_BBOX_FLAGS_S8
#include "main/dll/player_api.h"
#include "main/pause_menu_api.h"
#include "main/pi_dolphin.h"
#include "dolphin/os/OSCache.h"
#include "main/voxmaps.h"
#include "track/intersect_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/objmodel.h"
#include "main/newshadows.h"
#include "main/sky.h"
#include "main/newshadows_texture_api.h"
#include "main/acosf_api.h"
#include "main/tex_dolphin.h"
#include "main/sky_api.h"
#include "dolphin/gx/GXDispList.h"
#include "track/intersect_fog_api.h"
#include "main/objseq_api.h"
#include "main/dll/FRONT/n_options.h"
#include "main/lightmap_render_queue_api.h"
#include "main/lightmap_internal.h"
#include "main/objprint_dolphin_internal.h"

u8 gCloudLayerOverlayColor[4] = {0x20, 0x20, 0x20, 0};
GXColor gTexShaderAmbColor = {0xFF, 0xFF, 0xFF, 0xFF};
GXColor gTexLightmapAmbColor = {0xff, 0xff, 0xff, 0xff};
s8 gTexIndMtxScaleExp = -2;

extern f32 lbl_803DEBCC;
extern const f32 lbl_803DEBFC;
extern const f32 gTexIndMtxScale;
extern f32 lbl_803DEC28;
extern int lbl_803DEBB0;
extern IndTexMtx23 gTexIndMtxTable;
#define FRUSTUM_PLANE_COUNT 5
WarpDestination gRcpPendingWarpDest;
extern GXColor gTexShaderFogColor;
extern GXColor gTexLightmapFogColor;

/*
 * TexShadowRow - 0x10-stride rows of the pending-shadow queue at the head of
 * gLightmapDrawQueue (indexed by gLightmapDrawQueueCount, bumped after each lightmapQueueShadowRow push).
 * mapBlockRender_callList writes type (4/5 = object shadow, 6 = indirect
 * lightmap) into the queued shadow row.
 */
typedef struct TexShadowRow
{
    int unk0;
    int unk4;
    int unk8;
    int type;
} TexShadowRow;

extern TexShadowRow gLightmapDrawQueue[];

static u8 mapBlockBounds_HasCornerPastDepthThreshold(MapBlockBoundsRec* bounds, float* xform)
{
    Vec v;
    u32 i;
    f32 fbset;
    f32 timing;

    i = 0;
    timing = gTrackPackedCoordScale;
    fbset = lbl_803DEC28;
    while (1)
    {
        {
            switch (i)
            {
            case 0:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->minZ;
                break;
            case 1:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->minZ;
                break;
            case 2:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->minZ;
                break;
            case 3:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->minZ;
                break;
            case 4:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->maxZ;
                break;
            case 5:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->minY;
                v.z = (f32)bounds->maxZ;
                break;
            case 6:
                v.x = (f32)bounds->minX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->maxZ;
                break;
            case 7:
                v.x = (f32)bounds->maxX;
                v.y = (f32)bounds->maxY;
                v.z = (f32)bounds->maxZ;
                break;
            }
        }
        v.x = v.x * timing;
        v.y = v.y * timing;
        v.z = v.z * timing;
        PSMTXMultVec((MtxPtr)xform, &v, &v);
        if (v.z >= fbset)
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

#define SHADER_FLAGS(s) ((s)->flags)

void mapBlockRender_drawLightmapIndirectPasses(struct MapBlockData* blockData, Shader* shader,
                                               ModelRenderInstrsState* state, f32 (*viewMtx)[4])
{
    f32 passMtx[3][4];
    IndTexMtx23 indMtx;
    int noiseFrameCount;
    Texture** noiseTextures;
    MapBlockBoundsRec* bounds[1];
    u8 passCount;
    u8* byteBase;
    u32 bits;
    int bitPos;
    u32 flags;
    int i;

    bitPos = state->bit;
    {
        int off = bitPos >> 3;
        byteBase = state->instrs;
        bits = byteBase[off];
        byteBase += off;
        bits = bits | (u32)(byteBase[1] << 8);
        bits = bits | (u32)(byteBase[2] << 16);
    }
    state->bit = bitPos + 8;
    /* extract this cursor's 8-bit field (LSB-first: shift out the bits already
     * consumed within the byte, then mask the width) -> bounds-record index */
    bounds[0] = &blockData->displayLists[(bits >> (bitPos & 7)) & 0xff];
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
        PSMTXTrans(passMtx, 0.0f, 0.4f * (f32)(i + 1), 0.0f);
        PSMTXConcat(viewMtx, passMtx, passMtx);
        GXLoadPosMtxImm(passMtx, GX_PNMTX0);
        indMtx = gTexIndMtxTable;
        getNewShadowNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
        selectTexture(noiseTextures[(u8)i], 1);
        {
            f32 s = (f32)((i & 0xff) + 1) * gTexIndMtxScale;
            indMtx.m[0][0] = s * lbl_803DEBFC;
        }
        indMtx.m[1][1] = indMtx.m[0][0];
        GXSetIndTexMtx(GX_ITM_0, indMtx.m, gTexIndMtxScaleExp);
        GXCallDisplayList(bounds[0]->dlist, bounds[0]->dlistSize);
    }
}

Shader* mapBlockRender_setLightmapShader(struct MapBlockData* blockData, ModelRenderInstrsState* state)
{
    Shader* shader;
    u32 shaderIdx;
    u8* byteBase;
    GXColor fogColor;
    u32 bits;
    u32 bitPos;
    u8 ambColor[3];

    fogColor = gTexLightmapFogColor;
    bitPos = state->bit;
    {
        int off = (int)bitPos >> 3;
        byteBase = state->instrs;
        bits = byteBase[off];
        byteBase += off;
        bits |= (u32)byteBase[1] << 8;
        bits |= (u32)byteBase[2] << 16;
        state->bit = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = &blockData->shaders[shaderIdx];
    }
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    selectTexture(((ShaderLayer*)Shader_getLayer(shader, 0))->texture, 0);
    if ((SHADER_FLAGS(shader) & 4) != 0)
    {
        _gxSetFogParams();
    }
    else
    {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
    }
    if ((SHADER_FLAGS(shader) & 1) != 0 || (SHADER_FLAGS(shader) & 0x40000) != 0 ||
        (SHADER_FLAGS(shader) & 0x800) != 0 || (SHADER_FLAGS(shader) & 0x1000) != 0)
    {
        GXSetChanAmbColor(GX_COLOR0, gTexLightmapAmbColor);
        if ((SHADER_FLAGS(shader) & 0x40000) != 0)
        {
            GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        }
        else
        {
            GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        }
    }
    else
    {
        objGetSunColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
        GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
    }
    return shader;
}

void mapBlockRender_drawDimmedAabbLights(MapBlockBoundsRec* bounds, MapBlockData* block, float* viewMtx)
{
    ModelLightStruct** lightPtr;
    f32 posZ;
    f32 posY;
    f32 posX;
    int lightCount;
    u8 colorA;
    u8 colorB;
    u8 colorG;
    u8 colorR;

    {
        f32 fz = *(f32*)&playerMapOffsetZ;
        f32 fldZ = block->transform[2][3];
        f32 fldY = block->transform[1][3];
        f32 fx = *(f32*)&playerMapOffsetX;
        f32 fldX = block->transform[0][3];
        f32 ax0 = (f32)(bounds->minX >> 3) + fldX;
        f32 az0 = (f32)(bounds->minZ >> 3) + fldZ;
        f32 ax1 = (f32)(bounds->maxX >> 3) + fldX;
        f32 az1 = (f32)(bounds->maxZ >> 3) + fldZ;
        modelLightStruct_selectBrightestAabbLights(ax0 + fx, (f32)(bounds->minY >> 3) + fldY, az0 + fz, ax1 + fx,
                                                   (f32)(bounds->maxY >> 3) + fldY, az1 + fz,
                                                   gTexDimmedLightList, 2, &lightCount);
    }
    Rcp_ResetTextureStageState();
    setupCausticBaseTevStages(viewMtx);
    {
        u8* pColorA;
        u8* pColorB;
        u8* pColorG;
        f32* pPosZ;
        f32* pPosY;
        int i;

        i = 0;
        lightPtr = gTexDimmedLightList;
        pColorA = &colorA;
        pColorB = &colorB;
        pColorG = &colorG;
        pPosZ = &posZ;
        pPosY = &posY;
        for (; i < lightCount; lightPtr = lightPtr + 1, i = i + 1)
        {
            modelLightStruct_getDiffuseColor(*lightPtr, &colorR, pColorG, pColorB, pColorA);
            colorR = ((int)colorR >> 1) + ((int)colorR >> 2);
            colorG = ((int)colorG >> 1) + ((int)colorG >> 2);
            colorB = ((int)colorB >> 1) + ((int)colorB >> 2);
            modelLightStruct_getPosition(*lightPtr, &posX, pPosY, pPosZ);
            addPointLightDirectStages(modelLightStruct_getRadius(*lightPtr), (int*)&colorR, &posX);
        }
    }
    Rcp_ApplyTextureStageCounts();
    GXSetNumChans(1);
    GXSetCullMode(GX_CULL_BACK);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return;
}

u32 frustumTestAabbWithPlaneOffsets(f32 minX, f32 maxX, f32 minY, f32 maxY, f32 minZ, f32 maxZ, f32* planeOffsets)
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
        if ((nearX * plane[i].normalX + nearY * plane[i].normalY + nearZ * plane[i].normalZ + plane[i].distance +
                 planeOffsets[i] <
             0.0f) &&
            (farX * plane[i].normalX + farY * plane[i].normalY + farZ * plane[i].normalZ + plane[i].distance +
                 planeOffsets[i] <
             0.0f))
            return 0;
    }
    return 1;
}

static u8 mapBlockBounds_ComputeAndTestPlanes(MapBlockBoundsRec* bounds, struct MapBlockData* block,
                                              FrustumPlane* planes, int planeCount, f32* minX, f32* minY, f32* minZ,
                                              f32* maxX, f32* maxY, f32* maxZ)
{
    u8 cornerIndex;
    float nearX;
    float nearY;
    float nearZ;
    float farX;
    float farY;
    float farZ;
    int i;
    *maxX = (f32)(bounds->maxX >> 3) + block->transform[0][3];
    *minX = (f32)(bounds->minX >> 3) + block->transform[0][3];
    *maxY = (f32)(bounds->maxY >> 3) + block->transform[1][3];
    *minY = (f32)(bounds->minY >> 3) + block->transform[1][3];
    *maxZ = (f32)(bounds->maxZ >> 3) + block->transform[2][3];
    *minZ = (f32)(bounds->minZ >> 3) + block->transform[2][3];
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
             0.0f) &&
            (planes->distance + (farX * planes->normalX + farY * planes->normalY + farZ * planes->normalZ) <
             0.0f))
        {
            return 0;
        }
        planes++;
    }
    return 1;
}

void mapBlockRender_callList(u8 passSelect, u32 visArg, MapBlockData* block, Shader* shader,
                             ModelRenderInstrsState* state, float* mtx)
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
    GXColor chanColor;
    int i;
    u32 visible;
    u32 flags;
    u32 bits;
    int bitPos;
    int byteBase;

    {
        TexShadowRow* texGlobals;
        MapBlockBoundsRec* bounds[1];

        texGlobals = gLightmapDrawQueue;
        bitPos = state->bit;
        {
            int off = bitPos >> 3;
            byteBase = (int)state->instrs;
            bits = *(u8*)(byteBase + off);
            byteBase += off;
            bits = bits | (u32)(*(u8*)(byteBase + 1) << 8);
            bits = bits | (u32)(*(u8*)(byteBase + 2) << 16);
        }
        state->bit = bitPos + 8;
        bounds[0] = &block->displayLists[(bits >> (bitPos & 7)) & 0xff];
        if ((shader != NULL) && ((SHADER_FLAGS(shader) & 2) != 0))
        {
            return;
        }
        if (mapBlockBounds_ComputeAndTestPlanes(bounds[0], block, (FrustumPlane*)((u8*)texGlobals + 0x987c),
                                                FRUSTUM_PLANE_COUNT, &minX, &minY, &minZ, &maxX, &maxY, &maxZ) == 0)
        {
            return;
        }
        if (passSelect == 0)
        {
            flags = SHADER_FLAGS(shader);
            if ((flags & 0x80000000) != 0)
            {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, bounds[0]->selector);
                shadowType = 5;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount = gLightmapDrawQueueCount + 1;
            }
            else if (((flags & 0x40000000) != 0) || ((flags & 0x2000) != 0))
            {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, bounds[0]->selector);
                shadowType = 4;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount = gLightmapDrawQueueCount + 1;
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
                        modelLightStruct_selectBrightestAabbLights(
                            minX + playerMapOffsetX, minY, minZ + playerMapOffsetZ, maxX + playerMapOffsetX, maxY,
                            maxZ + playerMapOffsetZ, gTexBlockLightList, 2, &count);
                    }
                    if ((shader != NULL) &&
                        (((SHADER_FLAGS(shader) & 0x800) != 0 || ((SHADER_FLAGS(shader) & 0x1000) != 0))))
                    {
                        ObjSeq_copyDefaultColor(&chanColor);
                        chanColor.a = 0;
                        chanColor.b = 0;
                        chanColor.g = 0;
                        chanColor.r = 0;
                        if (count == 0)
                        {
                            if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0))
                            {
                                addLightColorModulateStage((int*)&chanColor);
                            }
                            else
                            {
                                addVertexAlphaDimStage((u8*)&chanColor);
                            }
                        }
                        else
                        {
                            modelLightStruct_getDiffuseColor(gTexBlockLightList[0], &lightColor[0], &lightColor[1],
                                                             &lightColor[2], &lightColor[3]);
                            modelLightStruct_getPosition(gTexBlockLightList[0], (f32*)&lightPos[0],
                                                         (f32*)&lightPos[1], (f32*)&lightPos[2]);
                            addFirstPointLightStages(modelLightStruct_getRadius(gTexBlockLightList[0]),
                                        (int*)lightColor, (f32*)&lightPos[0], (u8*)&chanColor);
                            for (i = 1; i < count; i = i + 1)
                            {
                                modelLightStruct_getDiffuseColor(gTexBlockLightList[i], &lightColor[0],
                                                                 &lightColor[1], &lightColor[2], &lightColor[3]);
                                modelLightStruct_getPosition(gTexBlockLightList[i], (f32*)&lightPos[0],
                                                             (f32*)&lightPos[1], (f32*)&lightPos[2]);
                                addPointLightAccumStages(modelLightStruct_getRadius(gTexBlockLightList[i]),
                                            (int*)lightColor, (f32*)&lightPos[0]);
                            }
                            if ((shader != NULL) && ((SHADER_FLAGS(shader) & 0x800) != 0))
                            {
                                addAccumulatedLightModulateStage();
                            }
                            else
                            {
                                addAccumulatedLightBlendStages();
                            }
                        }
                    }
                    else
                    {
                        for (i = 0; i < count; i = i + 1)
                        {
                            modelLightStruct_getDiffuseColor(gTexBlockLightList[i], &lightColor[0],
                                                             &lightColor[1], &lightColor[2], &lightColor[3]);
                            modelLightStruct_getPosition(gTexBlockLightList[i], (f32*)&lightPos[0],
                                                         (f32*)&lightPos[1], (f32*)&lightPos[2]);
                            addPointLightDirectStages(modelLightStruct_getRadius(gTexBlockLightList[i]),
                                        (int*)lightColor, (f32*)&lightPos[0]);
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
                            u8 mirrorVisible = mapBlockBounds_ComputeAndTestPlanes(
                                bounds[0], block, (FrustumPlane*)((u8*)texGlobals + 0x9818), FRUSTUM_PLANE_COUNT, &minX, &minY,
                                &minZ, &maxX, &maxY, &maxZ);
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
                            return;
                        }
                        addShadowFalloffTevStages();
                    }
                    Rcp_ApplyTextureStageCounts();
                }
            }
            GXCallDisplayList(bounds[0]->dlist, bounds[0]->dlistSize);
            flags = SHADER_FLAGS(shader);
            if ((((flags & 0x4000) != 0) || ((flags & 0x8000) != 0) || ((flags & 0x10000) != 0)) &&
                (mapBlockBounds_HasCornerPastDepthThreshold(bounds[0], mtx) != 0))
            {
                int shadowType;

                lightmapQueueShadowRow(bounds[0], block, 0x17);
                shadowType = 6;
                texGlobals[gLightmapDrawQueueCount].type = shadowType;
                gLightmapDrawQueueCount = gLightmapDrawQueueCount + 1;
            }
        }
    }
}

static void mapBlockRender_setupShaderTextures(Shader* shader, int mode)
{
    int layerIdx;
    ShaderLayer* layer;
    int texture;
    f32 (*texMtx)[4];
    int overrideIdx;
    int remain;
    MapTextureOverride* overrideEntry;
    u8 layerByte;
    u32 kColor;
    f32 tx;
    f32 texMatrix[3][4];

    kColor = lbl_803DEBB0;
    if ((shader->layerCount == 2) &&
        (texture = (int)Shader_getLayer(shader, 1),
         (((ShaderLayer*)texture)->typeBits & 0x7f) == 9u))
    {
        layer = Shader_getLayer(shader, 0);
        {
            u8 overrideType;
            if ((overrideType = layer->materialId) != '\0')
            {
                int layerTextureId = layer->textureIndex;
                MapTextureOverride* overrides;
                overrideIdx = 0;
                overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                overrideEntry = overrides;
                for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--)
                {
                    if (((overrideEntry->refCount > 0) &&
                         ((u32)overrideEntry->textureId == layerTextureId)) &&
                        ((int)overrideType == overrideEntry->type))
                    {
                        texture = (int)textureGetAnimationFrame((Texture*)layerTextureId,
                                                                overrides[overrideIdx].frame);
                        break;
                    }
                    overrideEntry = overrideEntry + 1;
                    overrideIdx = overrideIdx + 1;
                }
            }
            else
            {
                texture = layer->textureIndex;
            }
        }
        if (layer->scrollMtx != 0xff)
        {
            tx = gMapTextureScrolls[layer->scrollMtx].offsetX / 1048576.0f;
            PSMTXTrans(texMatrix, tx,
                       gMapTextureScrolls[layer->scrollMtx].offsetY /
                           1048576.0f,
                       0.0f);
            texMtx = texMatrix;
        }
        else
        {
            texMtx = NULL;
        }
        addTexLayerStageKColor((Texture*)texture, texMtx, 0, (GXColor*)&kColor);
        if ((SHADER_FLAGS(shader) & 0x100) != 0)
        {
            addSmallReflectionTevStage();
        }
        layer = Shader_getLayer(shader, 1);
        {
            u8 overrideType;
            if ((overrideType = layer->materialId) != '\0')
            {
                int layerTextureId = layer->textureIndex;
                MapTextureOverride* overrides;
                overrideIdx = 0;
                overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                overrideEntry = overrides;
                for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--)
                {
                    if (((overrideEntry->refCount > 0) &&
                         ((u32)overrideEntry->textureId == layerTextureId)) &&
                        ((int)overrideType == overrideEntry->type))
                    {
                        texture = (int)textureGetAnimationFrame((Texture*)layerTextureId,
                                                                overrides[overrideIdx].frame);
                        break;
                    }
                    overrideEntry = overrideEntry + 1;
                    overrideIdx = overrideIdx + 1;
                }
            }
            else
            {
                texture = layer->textureIndex;
            }
        }
        if (layer->scrollMtx != 0xff)
        {
            tx = gMapTextureScrolls[layer->scrollMtx].offsetX / 1048576.0f;
            PSMTXTrans(texMatrix, tx,
                       gMapTextureScrolls[layer->scrollMtx].offsetY /
                           1048576.0f,
                       0.0f);
            texMtx = texMatrix;
        }
        else
        {
            texMtx = NULL;
        }
        addTexLayerStage((Texture*)texture, texMtx, 9);
        addVertexColorKAlphaStage((GXColor*)&kColor);
    }
    else
    {
        for (layerIdx = 0; layerIdx < (int)(u32)shader->layerCount; layerIdx = layerIdx + 1)
        {
            int layerTextureId;
            layer = Shader_getLayer(shader, layerIdx);
            layerTextureId = layer->textureIndex;
            if ((u32)layerTextureId != 0)
            {
                u8 overrideType;
                {
                    if ((overrideType = layer->materialId) != '\0')
                    {
                        MapTextureOverride* overrides;
                        overrideIdx = 0;
                        overrides = (MapTextureOverride*)(int)gMapTextureOverrides;
                        overrideEntry = overrides;
                        for (remain = 0x50; remain != 0 || (texture = layerTextureId, 0); remain--)
                        {
                            if (((overrideEntry->refCount > 0) &&
                                 ((u32)overrideEntry->textureId == layerTextureId)) &&
                                ((int)overrideType == overrideEntry->type))
                            {
                                texture = (int)textureGetAnimationFrame(
                                    (Texture*)layerTextureId, overrides[overrideIdx].frame);
                                break;
                            }
                            overrideEntry = overrideEntry + 1;
                            overrideIdx = overrideIdx + 1;
                        }
                    }
                    else
                    {
                        texture = layerTextureId;
                    }
                    if (layer->scrollMtx != 0xff)
                    {
                        int scrollOffset = (u32)layer->scrollMtx * 0x10;
                        tx = ((MapTextureScroll*)((u8*)gMapTextureScrolls + scrollOffset))->offsetX / 1048576.0f;
                        PSMTXTrans(texMatrix, tx,
                                   ((MapTextureScroll*)((u8*)gMapTextureScrolls + scrollOffset))->offsetY / 1048576.0f,
                                   0.0f);
                        texMtx = texMatrix;
                    }
                    else
                    {
                        texMtx = NULL;
                    }
                    layerByte = layer->typeBits & 0x7f;
                    if ((SHADER_FLAGS(shader) & 0x40000) != 0)
                    {
                        addTexLayerStagesLit((void*)texture, texMtx);
                    }
                    else
                    {
                        addTexLayerStage((Texture*)texture, texMtx, layerByte);
                    }
                }
            }
            else
            {
                addVertexColorStage();
            }
        }
        if ((SHADER_FLAGS(shader) & 0x100) != 0)
        {
            addSmallReflectionTevStage();
        }
    }
    return;
}

Shader* mapBlockRender_setShader(u8 doSetup, MapBlockData* blockData, ModelRenderInstrsState* state) {
    Shader* shader;
    u32 shaderIdx;
    GXColor fogColor;
    u8* byteBase;
    u32 flags;
    int* cloudTex;
    u8 ambColor[3];
    u8 fogRgba[4];
    u32 bits;
    u32 bitPos;

    fogColor = gTexShaderFogColor;
    bitPos = state->bit;
    {
        int off = (int)bitPos >> 3;
        byteBase = state->instrs;
        bits = byteBase[off];
        byteBase += off;
        bits |= (u32)byteBase[1] << 8;
        bits |= (u32)byteBase[2] << 16;
        state->bit = bitPos + 6;
        shaderIdx = (bits >> (bitPos & 7)) & 0x3f;
        shader = &blockData->shaders[shaderIdx];
    }

    if (doSetup == 0) {
        return shader;
    }

    if ((SHADER_FLAGS(shader) & 4) != 0) {
        _gxSetFogParams();
    } else {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
    }
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x80000000) != 0)) {
        return shader;
    }
    if ((shader != 0) && ((SHADER_FLAGS(shader) & 0x20000) != 0)) {
        u32 res;
        res = AttractMovie_DrawTextureCallback(0, 0, 0);
        if ((res & 0xff) != 0) {
            return shader;
        }
    }
    Rcp_ResetTextureStageState();
    if ((SHADER_FLAGS(shader) & 0x80) != 0) {
        setupHeatShimmerTevStages((char*)shader);
    } else {
        mapBlockRender_setupShaderTextures(shader, 0x80);
    }
    flags = SHADER_FLAGS(shader);
    if ((flags & 0x20) != 0 && (cloudTex = gCloudLayerTexture) != 0) {
        addSignedOverlayTexStage((u8*)cloudTex, &gCloudLayerTexMatrix, gCloudLayerOverlayColor);
    } else if ((flags & 0x40) != 0) {
        addWarpedRingTevStages();
    } else if (isHeavyFogEnabled()) {
        getFogColorRgb(fogRgba);
        renderHeavyFog(fogRgba);
    }
    if (((SHADER_FLAGS(shader) & 0x40000000) != 0) || ((SHADER_FLAGS(shader) & 0x20000000) != 0)) {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    } else if ((SHADER_FLAGS(shader) & 0x400) != 0 && (SHADER_FLAGS(shader) & 0x80) == 0) {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
        gxSetPeControl_ZCompLoc_(0);
        GXSetAlphaCompare(GX_GREATER, 0, GX_AOP_AND, GX_GREATER, 0);
    } else {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    }
    if ((SHADER_FLAGS(shader) & 1) != 0 || (SHADER_FLAGS(shader) & 0x40000) != 0 ||
        (SHADER_FLAGS(shader) & 0x800) != 0 || (SHADER_FLAGS(shader) & 0x1000) != 0) {
        GXSetChanAmbColor(GX_COLOR0, gTexShaderAmbColor);
        if ((SHADER_FLAGS(shader) & 0x40000) != 0) {
            GXSetChanCtrl(GX_COLOR0, GX_DISABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        } else {
            GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        }
    } else {
        objGetSunColor(0, &ambColor[0], &ambColor[1], &ambColor[2]);
        GXSetChanCtrl(GX_COLOR0, GX_ENABLE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanAmbColor(GX_COLOR0, *(GXColor*)&ambColor[0]);
    }
    if ((SHADER_FLAGS(shader) & 0x8) != 0) {
        GXSetCullMode(GX_CULL_BACK);
    } else {
        GXSetCullMode(GX_CULL_NONE);
    }
    return shader;
}

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


/* TrackTriangle -- the 0x4c-byte collision triangle record packed into
 * gTrackTriangleBuffer.  Plane and edge-plane normals are prebaked f32;
 * vertex coordinates are stored as s16 triplets grouped by axis
 * (x0 x1 x2 / y0 y1 y2 / z0 z1 z2), which the hit-detect code reads both
 * by field and as an s16 index off the record base. */
typedef struct TrackTriangle
{
    f32 planeD;     /* 0x00 plane equation constant */
    f32 planeN[3];  /* 0x04 plane normal xyz */
    s16 vx[3];      /* 0x10 vertex x coords */
    s16 vy[3];      /* 0x16 vertex y coords */
    s16 vz[3];      /* 0x1c vertex z coords */
    u8 pad22[2];    /* 0x22 */
    f32 edgeN0[3];  /* 0x24 edge 0 outward normal */
    f32 edgeN1[3];  /* 0x30 edge 1 outward normal */
    f32 edgeN2[3];  /* 0x3c edge 2 outward normal */
    u8 surfaceType; /* 0x48 copied into intersect-line records */
    s8 flags;       /* 0x49 0x10 = disabled, 0x4 = force */
    u8 minMaxY;     /* 0x4a lo/hi nibble: s16 index (base 0xb) of min/max height */
    u8 edgeOutBits; /* 0x4b per-edge outside bits from last query */
} TrackTriangle;


extern volatile PPCWGPipe GXWGFifo : (0xCC008000);
extern int sSynthFadeUnit;
extern int renderFlags;
extern f32 lbl_803DEBDC;
extern f32 lbl_803DEC40;

static inline void GXPosition3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void GXTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

void* trackGetBlockDescriptors(u32* outVal);

void mapBlockRender_setVtxDcrs(u8 doSetup, MapBlockData* block, Shader* shader,
                               ModelRenderInstrsState* state)
{
    int* stateWords;
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

    stateWords = (int*)state;
    if (doSetup != 0)
    {
        GXClearVtxDesc();
    }
    pos = state->bit;
    off = pos >> 3;
    val = *(u8*)(stateWords[0] + off);
    p = (u8*)stateWords[0] + off;
    val |= p[1] << 8;
    val |= p[2] << 16;
    state->bit = pos + 1;
    bit = (val >> (pos & 7)) & 1;
    if (doSetup != 0)
    {
        GXSetVtxDesc(GX_VA_POS, bit ? GX_INDEX16 : GX_INDEX8);
    }
    pos2 = state->bit;
    off2 = pos2 >> 3;
    val2 = *(u8*)(stateWords[0] + off2);
    q = (u8*)stateWords[0] + off2;
    val2 |= q[1] << 8;
    val2 |= q[2] << 16;
    state->bit = pos2 + 1;
    bit2 = (val2 >> (pos2 & 7)) & 1;
    if (doSetup != 0)
    {
        GXSetVtxDesc(GX_VA_CLR0, bit2 ? GX_INDEX16 : GX_INDEX8);
    }
    pos3 = state->bit;
    off3 = pos3 >> 3;
    val3 = *(u8*)(stateWords[0] + off3);
    r = (u8*)stateWords[0] + off3;
    val3 |= r[1] << 8;
    val3 |= r[2] << 16;
    state->bit = pos3 + 1;
    bit3 = (val3 >> (pos3 & 7)) & 1;
    if (doSetup != 0)
    {
        if (shader != NULL && (shader->flags & 0x80000000) == 0)
        {
            for (i = 0; i < shader->layerCount; i++)
            {
                GXSetVtxDesc(i + GX_VA_TEX0, bit3 ? GX_INDEX16 : GX_INDEX8);
            }
        }
        else
        {
            GXSetVtxDesc(GX_VA_TEX0, bit3 ? GX_INDEX16 : GX_INDEX8);
        }
    }
}


void setupToRenderMapBlock(MapBlockData* block, void* posMtx)
{
    Mtx out;
    Mtx tmp;
    f32 fc;

    GXLoadPosMtxImm((const f32 (*)[4])posMtx, GX_PNMTX0);
    PSMTXCopy((MtxPtr)posMtx, tmp);
    fc = 0.0f;
    tmp[0][3] = fc;
    tmp[1][3] = fc;
    tmp[2][3] = fc;
    GXLoadNrmMtxImm(tmp, GX_PNMTX0);
    PSMTXConcat((MtxPtr)gCameraLightPerspectiveMatrix, (MtxPtr)posMtx, out);
    GXLoadTexMtxImm(out, GX_TEXMTX2, GX_MTX3x4);
    GXSetArray(GX_VA_POS, block->vertices, 6);
    GXSetArray(GX_VA_CLR0, block->vertexColors, 2);
    GXSetArray(GX_VA_TEX0, block->vertexTexCoords, 4);
    GXSetArray(GX_VA_TEX1, block->vertexTexCoords, 4);
}

void renderMapBlock(MapBlockData* block, u8 type)
{
    ModelRenderInstrsState state;
    f32 m[16];
    void* instructions;
    int done;
    Shader* shader;
    u8 doSetup;
    u16 instructionCount;
    void* viewMtx;

    shader = NULL;
    doSetup = FALSE;
    if (type == 1)
    {
        instructions = block->renderInstrsTransp;
        instructionCount = block->nRenderInstrsTransp;
    }
    else if (type == 2)
    {
        instructions = block->renderInstrsWater;
        instructionCount = block->nRenderInstrsWater;
    }
    else
    {
        instructions = block->renderInstrsMain;
        instructionCount = block->nRenderInstrsMain;
        doSetup = TRUE;
    }
    if (instructionCount == 0)
        return;
    viewMtx = Camera_GetViewMatrix();
    PSMTXConcat((MtxPtr)viewMtx, block->transform, (MtxPtr)m);
    if (doSetup)
        setupToRenderMapBlock(block, m);
    modelRenderInstrsState_init(&state, instructions, instructionCount << 3, instructionCount << 3);
    done = FALSE;
    while (!done)
    {
        u32 word;
        int op;
        int pos;
        int off = (pos = state.bit) >> 3;
        u8* base;
        u8* bp;

        base = state.instrs;
        bp = base + off;
        word = bp[0];
        word |= bp[1] << 8;
        word |= bp[2] << 16;
        state.bit = pos + 4;
        op = (word >> (pos & 7)) & 0xf;
        switch (op)
        {
        case 3:
            mapBlockRender_setVtxDcrs(doSetup, block, shader, &state);
            break;
        case 1:
            shader = mapBlockRender_setShader(doSetup, block, &state);
            break;
        case 2:
            mapBlockRender_callList(doSetup, 0, block, shader, &state, m);
            break;
        case 4:
        {
            u32 word2;
            int cnt;
            int i;
            u8* bp2;
            ModelRenderInstrsState* sp = &state;
            int pos2 = pos + 4;
            bp2 = base + (pos2 >> 3);
            word2 = bp2[0];
            word2 |= bp2[1] << 8;
            word2 |= bp2[2] << 16;
            state.bit = pos2 + 4;
            cnt = (word2 >> (pos2 & 7)) & 0xf;
            for (i = 0; i < cnt; i++)
                modelRenderInstrsState_advance(sp, 8);
            break;
        }
        case 5:
            done = TRUE;
            break;
        }
    }
}

void renderGlows(void)
{
    f32 px, py, pz;
    s32 sx, sy, sz;
    u8 amb[3];
    GXColor fogCol;
    Mtx sunMtx;
    Vec dir;
    Vec cam;
    MtxPtr viewMtx;
    u8 alpha;
    u8 sunAlpha;
    f32 sunDot;
    int i;
    ModelLightStruct* e;

    fogCol = *(GXColor*)&sSynthFadeUnit;
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    gxTevResetStages();
    gxTevColor1TexAlphaStage();
    gxTevCommitStages();
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogCol);
    gxSetAdditiveBlendNoZTest();
    alpha = 0xff;
    gSunFlareScissorWidth = 0;
    gSunFlareScissorHeight = 0;
    sunAlpha = skyGetSunRenderAlpha(2);
    if (sunAlpha != 0 && (renderFlags & 0x40))
    {
        viewMtx = (MtxPtr)Camera_GetViewMatrix();
        skyGetSunLightDirection(0, &dir.x, &dir.y, &dir.z);
        cam.x = viewMtx[2][0];
        cam.y = viewMtx[2][1];
        cam.z = viewMtx[2][2];
        sunDot = PSVECDotProduct(&dir, &cam);
        if (sunDot > 0.0f)
        {
            int occ;
            f32 fade;
            skyBuildSunModelMatrix(sunMtx);
            Camera_ProjectWorldPointWithOffset(sunMtx[0][3], sunMtx[1][3], sunMtx[2][3], 100.0f, &px, &py, &pz);
            Camera_ClipToScreen(px, py, pz, &sx, &sy, &sz);
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
                int d = depthReadRequestPoll(sx + gSunOcclusionSampleOffsets[i].x,
                                             sy + gSunOcclusionSampleOffsets[i].y, (void*)i);
                if (sz <= d && pauseMenuGetState() == 0)
                    occ++;
            }
            fade = (f32)(u32)occ / 5.0f - gSunFlareFade;
            if (fade > 0.0125f)
                fade = 0.0125f;
            else if (fade < -0.0125f)
                fade = -0.0125f;
            gSunFlareFade = gSunFlareFade + fade;
            sunDot = sunDot * gSunFlareFade;
            if (sunDot > 0.0f)
            {
                PSMTXConcat(viewMtx, sunMtx, sunMtx);
                GXLoadPosMtxImm((const f32 (*)[4])sunMtx, GX_PNMTX0);
                GXSetCurrentMtx(GX_PNMTX0);
                selectTexture(skyGetSkyTexture(), 0);
                skyGetSunColor(0, &amb[0], &amb[1], &amb[2]);
                sunDot = (f32)(u32)sunAlpha * sunDot;
                _gxSetTevColor2(amb[0], amb[1], amb[2], (int)(0.5f * sunDot));
                alpha = 255.0f - 0.9f * sunDot;
                fade = 20000.0f * sunDot;
                sunDot = fade * lbl_803DEC40;
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                GXPosition3f32(-sunDot, -sunDot, lbl_803DEBCC);
                GXTexCoord2f32(lbl_803DEBCC, lbl_803DEBCC);
                GXPosition3f32(sunDot, -sunDot, lbl_803DEBCC);
                GXTexCoord2f32(lbl_803DEBDC, lbl_803DEBCC);
                GXPosition3f32(sunDot, sunDot, lbl_803DEBCC);
                GXTexCoord2f32(lbl_803DEBDC, lbl_803DEBDC);
                GXPosition3f32(-sunDot, sunDot, lbl_803DEBCC);
                GXTexCoord2f32(lbl_803DEBCC, lbl_803DEBDC);
            }
        }
    }
    colorScale = alpha;
    if (gGlowLightCount != 0)
    {
        for (i = 0; i < gGlowLightCount; i++)
        {
            int d;
            e = gGlowLightList[i];
            Camera_ProjectWorldPointWithOffset(e->worldX - playerMapOffsetX, e->worldY, e->worldZ - playerMapOffsetZ,
                                               e->glowProjectionRadius, &px, &py, &pz);
            Camera_ClipToScreen(px, py, pz, &sx, &sy, &sz);
            d = depthReadRequestPoll(sx, sy, e);
            if (sz <= d && pauseMenuGetState() == 0)
                e->glowAlphaStep = 0x10;
            else
                e->glowAlphaStep = -0x10;
        }
        GXSetCurrentMtx(GX_IDENTITY);
        gxTevColor1TexAlphaStage();
        gxSetAdditiveBlendNoZTest();
        for (i = 0; i < gGlowLightCount; i++)
        {
            e = gGlowLightList[i];
            if (e->glowAlpha != 0)
            {
                selectTexture((Texture*)e->glowTexture, 0);
                _gxSetTevColor2((int)((f32)(u32)e->glowColor[0] * e->activeIntensity),
                                (int)((f32)(u32)e->glowColor[1] * e->activeIntensity),
                                (int)((f32)(u32)e->glowColor[2] * e->activeIntensity),
                                (u8)((int)(e->glowColor[3] * e->glowAlpha) >> 8));
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                GXPosition3f32(e->viewX - e->glowScale, e->viewY - e->glowScale, e->viewZ);
                GXTexCoord2f32(lbl_803DEBCC, lbl_803DEBCC);
                GXPosition3f32(e->viewX + e->glowScale, e->viewY - e->glowScale, e->viewZ);
                GXTexCoord2f32(lbl_803DEBDC, lbl_803DEBCC);
                GXPosition3f32(e->viewX + e->glowScale, e->viewY + e->glowScale, e->viewZ);
                GXTexCoord2f32(lbl_803DEBDC, lbl_803DEBDC);
                GXPosition3f32(e->viewX - e->glowScale, e->viewY + e->glowScale, e->viewZ);
                GXTexCoord2f32(lbl_803DEBCC, lbl_803DEBDC);
            }
        }
        GXSetCurrentMtx(GX_PNMTX0);
    }
}

void getSunFlareScissorRect(int* outX, int* outY, int* outWidth, int* outHeight)
{
    *outX = gSunFlareScissorX;
    *outY = gSunFlareScissorY;
    *outWidth = gSunFlareScissorWidth;
    *outHeight = gSunFlareScissorHeight;
}

static inline int isGlowInFrustum(ModelLightStruct* light)
{
    FrustumPlane* plane;
    u8 i;
    f32 offsetX;
    f32 offsetZ;
    f32 bias;

    i = 0;
    offsetZ = playerMapOffsetZ;
    offsetX = playerMapOffsetX;
    bias = lbl_803DEBCC;
    for (; i < 5; i++)
    {
        f32 dot;
        plane = &gViewFrustumPlanes[i];
        dot = light->worldY * plane->normalY + plane->normalX * (light->worldX - offsetX) +
                  plane->normalZ * (light->worldZ - offsetZ) + plane->distance + bias;
        if (dot < bias)
        {
            return 0;
        }
    }
    return 1;
}

void queueGlowRender(ModelLightStruct* light)
{
    int visible;
    u8 idx;

    if (gGlowLightCount >= 100)
        return;

    visible = isGlowInFrustum(light);
    {
        u8 vis = visible;
        if (vis == 0 && light->glowAlpha == 0)
            return;
        if (vis == 0)
        {
            light->glowAlphaStep = -0x10;
        }
    }
    idx = gGlowLightCount++;
    gGlowLightList[idx] = light;
}

void trackPackVector(short* out, float* vec)
{
    int yScaled;
    int zScaled;

    yScaled = (int)(8.0f * vec[1]);
    zScaled = (int)(8.0f * vec[2]);
    *out = (short)(int)(8.0f * *vec);
    out[1] = yScaled;
    out[2] = zScaled;
}

void trackUnpackVector(s16* in, f32* out)
{
    out[0] = (f32)(s32)in[0] * gTrackPackedCoordScale;
    out[1] = (f32)(s32)in[1] * gTrackPackedCoordScale;
    out[2] = (f32)(s32)in[2] * gTrackPackedCoordScale;
}

/* trackBuildModelTriangles -- gather model triangles overlapping a swept bbox into the
 * hit-detect triangle buffer at cur (0x4c-byte records); returns advanced
 * cursor. */

u32 trackGetPackedSurfaceType(int* obj)
{
    u32 v = obj[4];
    v &= 0x00FF0000;
    return v >> 16;
}

int mapBlockGetPolygonGroupType(void* obj)
{
    return (((MapTriGroup*)obj)->flags & 0xff000000) >> 24;
}

int mapBlockCountTrianglesByType(MapBlockData* block, int type)
{
    MapTriGroup* entry;
    int offset;
    int total;
    int i;
    int count;
    total = 0;
    offset = 0;
    count = block->polyGroupCount;
    for (i = 0; i < count; i++)
    {
        entry = (MapTriGroup*)((u8*)block->polygonGroups + offset);
        if (type == (int)((entry->flags & 0xff000000) >> 24))
        {
            total += entry[1].firstTri - entry->firstTri;
        }
        offset += 0x14;
    }
    return total;
}

void* mapBlockGetPolygon(MapBlockData* obj, int idx)
{
    return (char*)obj->gcPolygons + idx * 8;
}

MapTriGroup* mapBlockGetPolygonGroup(MapBlockData* obj, int idx)
{
    return (MapTriGroup*)obj->polygonGroups + idx;
}

MapBlockBoundsRec* mapBlockGetDisplayListBounds(MapBlockData* obj, int idx)
{
    return &obj->displayLists[idx];
}

Shader* mapBlockGetShader(MapBlockData* obj, int idx)
{
    return obj->shaders + idx;
}

void MapBlock_initShaders(MapBlockData* block)
{
    int i;
    int j;
    int ref;
    Shader* sh;
    for (i = 0; i < block->shaderCount; i++)
    {
        sh = &block->shaders[i];
        for (j = 0; j < sh->layerCount; j++)
        {
            ref = sh->layers[j].textureIndex;
            if (ref != -1)
            {
                sh->layers[j].texture = block->textures[ref].texture;
                ref = sh->layers[j].materialId;
                if ((u32)ref != 0u)
                {
                    mapTextureOverrideAcquire(sh->layers[j].texture, 0, ref);
                }
            }
            else
            {
                sh->layers[j].texture = NULL;
            }
            sh->layers[j].scrollMtx = 0xff;
        }
        ref = sh->auxTextureIndex;
        if (ref != -1)
        {
            sh->auxTexture = block->textures[ref].texture;
        }
        else
        {
            sh->auxTexture = NULL;
        }
    }
}

static inline void* mapBlockRelocatePointer(MapBlockData* block, void* offset)
{
    return (u8*)block + (u32)offset;
}

void MapBlock_init(MapBlockData* block)
{
    int i;

    if (block->textures != NULL)
        block->textures = mapBlockRelocatePointer(block, block->textures);
    if (block->gcPolygons != NULL)
        block->gcPolygons = mapBlockRelocatePointer(block, block->gcPolygons);
    if (block->polygonGroups != NULL)
        block->polygonGroups = mapBlockRelocatePointer(block, block->polygonGroups);
    block->vertices = mapBlockRelocatePointer(block, block->vertices);
    block->vertexColors = mapBlockRelocatePointer(block, block->vertexColors);
    block->vertexTexCoords = mapBlockRelocatePointer(block, block->vertexTexCoords);
    if (block->renderInstrsMain != NULL)
        block->renderInstrsMain = mapBlockRelocatePointer(block, block->renderInstrsMain);
    if (block->renderInstrsTransp != NULL)
        block->renderInstrsTransp = mapBlockRelocatePointer(block, block->renderInstrsTransp);
    if (block->renderInstrsWater != NULL)
        block->renderInstrsWater = mapBlockRelocatePointer(block, block->renderInstrsWater);
    block->displayLists = mapBlockRelocatePointer(block, block->displayLists);
    if (block->shaders != NULL)
        block->shaders = mapBlockRelocatePointer(block, block->shaders);

    for (i = 0; i < block->displayListCount; i++)
    {
        block->displayLists[i].dlist = mapBlockRelocatePointer(block, block->displayLists[i].dlist);
    }
}

void MapBlock_initHits(MapBlockData* block, int index)
{
    int i;
    int* table = (int*)gHitsTab;
    int fileOff = table[index];
    int size = table[index + 1] - fileOff;
    MapHitLine* entry;
    s16 value;

    if (size > 0)
    {
        block->hits = mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(MLDF_FILEID_HITS_BIN, block->hits, fileOff, size);
    }
    block->hitCount = (u32)size / sizeof(MapHitLine);
    i = 0;
    while (i < block->hitCount)
    {
        entry = &block->hits[i];
        if (entry->x[0] < 0 || (value = entry->x[1]) < 0 || entry->x[0] > 0x280 || value > 0x280)
        {
            entry->kind = 0x40;
        }
        entry = &block->hits[i];
        if (entry->z[0] < 0 || (value = entry->z[1]) < 0 || entry->z[0] > 0x280 || value > 0x280)
        {
            entry->kind = 0x40;
        }
        i++;
    }
    block->auxData = NULL;
    block->unk9E = 0;
    block->flags4 &= ~0x40;
}

MapBlockData* MapBlock_loadFromFile(int blockId)
{
    int compressedLen;
    int decompressedSize;
    void* buf;
    int blockOff = 0;
    int* table;
    int tableEntry;
    if (blockId <= gMapBlockIndexCount)
    {
        table = gMapBlockIndexList;
        if (table != 0)
        {
            tableEntry = table[blockId];
            if (tableEntry != -1)
            {
                if (tableEntry != 0 || table[blockId + 1] != 0)
                {
                    blockOff = tableEntry;
                    checkLoadBlock(tableEntry, &compressedLen, &decompressedSize);
                }
                else
                {
                    return 0;
                }
            }
        }
    }
    else
    {
        return 0;
    }
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
    loadAndDecompressDataFile(MLDF_FILEID_BLOCKS_BIN_A, buf, blockOff, compressedLen, 0, 0, 0);
    return buf;
}

void mapBlockGpuRecoveryHook(void)
{
    int n;
    int i;

    i = 0;
    n = gMapBlockCount;
    for (; i < n; i++)
    {
    }
}

void* mapBlockGetUnused00Value(MapBlockData* block)
{
    return NULL;
}

void mapGetBlocks(void** outLayerTables, u32* outBlocks)
{
    *outLayerTables = gMapBlockLayerTables;
    *outBlocks = (u32)gMapBlocks;
}

void mapClearBlockEdgeFlags(void)
{
    int i;
    int j;
    MapBlockData* block;

    for (i = 0; i < gMapBlockCount; i++)
    {
        block = gMapBlocks[i];
        if (block != NULL)
        {
            for (j = 0; j < block->displayListCount; j++)
            {
                block->displayLists[j].flags = 0;
            }
        }
    }
}

int collectShadowTrackTriangles(GameObject* obj, int triBuf, void* planesOut, int vertsOut, int unusedTriangleCount,
                                f32 offX, f32 offZ, int unusedRenderMode, int kindSelector)
{
    int j;
    f32 lm[12];
    u8* descBytes = trackGetBlockDescriptors((u32*)&j);
    u8* end = descBytes + j * 0x18;
    int total;
    int grp;
    int outOff;
    int triangleFlag;

    outOff = 0;
    j = grp = 0;
    total = 0;
    triangleFlag = kindSelector ? 4 : 8;
    for (; descBytes < end; descBytes += 0x18)
    {
        u32 id = *(u32*)descBytes;
        if (id == 0 || id == *(u32*)&obj->anim.parent)
        {
            f32 fx = obj->anim.localPosX;
            f32 fz = obj->anim.localPosZ;
            TrackShadowTriangle* outA;

            if (id == 0)
            {
                fx -= offX;
                fz -= offZ;
            }
            j = (s16)((TrackBlockDescriptor*)descBytes)->firstTriangle;
            outA = (TrackShadowTriangle*)((char*)planesOut + outOff);
            while (j < (s16)((TrackBlockDescriptor*)descBytes)[1].firstTriangle && grp < 0x4b0 && total < 0xe10)
            {
                if (triangleFlag & ((TrackTriangle*)triBuf + j)->flags)
                {
                    ((TrackP6Entry*)vertsOut)->relX0 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[0]) - fx;
                    ((TrackP6Entry*)vertsOut)->relY0 =
                        __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[0]) - obj->anim.localPosY;
                    ((TrackP6Entry*)vertsOut)->relZ0 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[0]) - fz;
                    ((TrackP6Entry*)vertsOut)->relX1 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[1]) - fx;
                    ((TrackP6Entry*)vertsOut)->relY1 =
                        __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[1]) - obj->anim.localPosY;
                    ((TrackP6Entry*)vertsOut)->relZ1 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[1]) - fz;
                    ((TrackP6Entry*)vertsOut)->relX2 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[2]) - fx;
                    ((TrackP6Entry*)vertsOut)->relY2 =
                        __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[2]) - obj->anim.localPosY;
                    ((TrackP6Entry*)vertsOut)->relZ2 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[2]) - fz;
                    outA->normal.x = ((TrackTriangle*)triBuf + j)->planeN[0];
                    outA->normal.y = ((TrackTriangle*)triBuf + j)->planeN[1];
                    outA->normal.z = ((TrackTriangle*)triBuf + j)->planeN[2];
                    outA->flags = ((TrackTriangle*)triBuf + j)->flags;
                    vertsOut += 0x24;
                    total += 3;
                    outA++;
                    grp += 1;
                    outOff += 0x14;
                }
                j++;
            }
        }
        else
        {
            f32* m = *(f32**)((char*)descBytes + 0xc);
            f32* p6start;
            int totalStart;
            TrackShadowTriangle* outA;

            lm[0] = m[0];
            lm[1] = m[4];
            lm[2] = m[8];
            lm[3] = m[12] - obj->anim.localPosX;
            lm[4] = m[1];
            lm[5] = m[5];
            lm[6] = m[9];
            lm[7] = m[13] - obj->anim.localPosY;
            lm[8] = m[2];
            lm[9] = m[6];
            lm[10] = m[10];
            lm[11] = m[14] - obj->anim.localPosZ;
            p6start = (f32*)vertsOut;
            totalStart = total;
            j = (s16)((TrackBlockDescriptor*)descBytes)->firstTriangle;
            outA = (TrackShadowTriangle*)((char*)planesOut + outOff);
            while (j < (s16)((TrackBlockDescriptor*)descBytes)[1].firstTriangle && grp < 0x4b0 && total < 0xe10)
            {
                if (triangleFlag & ((TrackTriangle*)triBuf + j)->flags)
                {
                    ((TrackP6Entry*)vertsOut)->relX0 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[0]);
                    ((TrackP6Entry*)vertsOut)->relY0 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[0]);
                    ((TrackP6Entry*)vertsOut)->relZ0 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[0]);
                    ((TrackP6Entry*)vertsOut)->relX1 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[1]);
                    ((TrackP6Entry*)vertsOut)->relY1 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[1]);
                    ((TrackP6Entry*)vertsOut)->relZ1 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[1]);
                    ((TrackP6Entry*)vertsOut)->relX2 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vx[2]);
                    ((TrackP6Entry*)vertsOut)->relY2 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vy[2]);
                    ((TrackP6Entry*)vertsOut)->relZ2 = __OSs16tof32(&((TrackTriangle*)triBuf + j)->vz[2]);
                    outA->normal.x = ((TrackTriangle*)triBuf + j)->planeN[0];
                    outA->normal.y = ((TrackTriangle*)triBuf + j)->planeN[1];
                    outA->normal.z = ((TrackTriangle*)triBuf + j)->planeN[2];
                    outA->flags = ((TrackTriangle*)triBuf + j)->flags;
                    vertsOut += 0x24;
                    total += 3;
                    outA++;
                    grp += 1;
                    outOff += 0x14;
                }
                j++;
            }
            if (totalStart < total)
            {
                PSMTXMultVecArray((MtxPtr)lm, (Vec*)p6start, (Vec*)p6start, total - totalStart);
            }
        }
    }
    return grp;
}

FrustumPlane gViewFrustumPlanes[FRUSTUM_PLANE_COUNT];
FrustumPlane gPlayerRelativeFrustumPlanes[FRUSTUM_PLANE_COUNT];
