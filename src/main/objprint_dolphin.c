#include "game/objects/object.h"
#include "main/texture.h"
#include "main/model_light.h"
#include "main/rcp_dolphin_api.h"
#include "main/frame_timing.h"
#include "main/objprint_render_api.h"
#include "main/objprint_dolphin_api.h"
#include "main/model.h"
#include "sys/objects.h"
#include "main/objlib_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/audio/sfx.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "main/mm.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/acosf.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_fog_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/objprint_internal.h"
#include "main/dll/partfx_interface.h"
#include "dolphin/os/OSReport.h"
#include "main/gameloop_api.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_dolphin.h"
#include "main/pi_flush_api.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/model_render_instrs_api.h"
#include "main/model_runtime_api.h"
#include "main/object_transform.h"
#include "main/map_load.h"
#include "main/objprint_load_api.h"
#include "main/objprint_api.h"
#include "main/table_file.h"
#include "main/fileio.h"
#include "main/vecmath.h"
#include "main/camera.h"
#include "dolphin/gx/GXDispList.h"
#include "main/dll/FRONT/n_options.h"
#include "main/dll/dll_80136a40.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_texture_api.h"
#include "dolphin/os.h"
#include "dolphin/mtx/vec.h"
#include "main/objprint_dolphin_internal.h"
#include "main/dll/ppcwgpipe_struct.h"

extern s32 gModelMtxCacheState;
extern s32 gObjFuzzLayerIndex;
extern u8 gObjFuzzPassActive;
extern GXColor lbl_803DB468;

static const GXColor sObjFuzzSavedEnvColor = {0xD8, 0xE0, 0xFF, 0xFF};
static const GXColorS10 sObjFuzzWhiteColorS10 = {0xFF, 0xFF, 0xFF, 0xFF};
static const GXColor sObjFuzzWhiteColor = {0xFF, 0xFF, 0xFF, 0xFF};
static const GXColor sObjFuzzDirLightEnvColor = {0xD8, 0xE0, 0xFF, 0xFF};


int objNormalizeRotationMatrix(f32* matrix, f32* out)
{
    Vec v3;
    Vec v1;
    Vec v2;
    f32 zero;

    v1.x = matrix[0];
    v1.y = matrix[1];
    v1.z = matrix[2];
    v2.x = matrix[4];
    v2.y = matrix[5];
    v2.z = matrix[6];
    v3.x = matrix[8];
    v3.y = matrix[9];
    v3.z = matrix[10];
    zero = 0.0f;

    if ((v1.x == zero && v1.y == zero && v1.z == zero) ||
        (v2.x == zero && v2.y == zero && v2.z == zero) ||
        (v3.x == zero && v3.y == zero && v3.z == zero))
    {
        return 0;
    }

    PSVECNormalize(&v1, &v1);
    PSVECNormalize(&v2, &v2);
    PSVECNormalize(&v3, &v3);

    out[0] = v1.x;
    out[1] = v1.y;
    out[2] = v1.z;
    out[3] = zero;
    out[4] = v2.x;
    out[5] = v2.y;
    out[6] = v2.z;
    out[7] = zero;
    out[8] = v3.x;
    out[9] = v3.y;
    out[10] = v3.z;
    out[11] = zero;
    return 1;
}


int objMatrixToRotation(f32* m, s16* outA, s16* outB, s16* outC)
{
    f32 buf[12];
    f32 x;
    f32 y;
    f32 z;

    if (objNormalizeRotationMatrix(m, buf) == 0)
    {
        return 0;
    }
    x = asinf(-buf[6]);
    if (x < 1.5707964f)
    {
        if (x > -1.5707964f)
        {
            y = atan2f_fast(buf[2], buf[10]);
            z = atan2f_fast(buf[4], buf[5]);
        }
        else
        {
            y = atan2f_fast(buf[1], buf[0]);
            z = 0.0f;
            y = z - y;
        }
    }
    else
    {
        y = atan2f_fast(buf[1], buf[0]);
        z = 0.0f;
        y = y - z;
    }
    *outC = (s16)(s32)(65536.0f * z / 6.2831855f);
    *outB = (s16)(s32)(65536.0f * x / 6.2831855f);
    *outA = (s16)(s32)(65536.0f * y / 6.2831855f);
    return 1;
}


void modelBuildPosNrmMtxs(ModelFileHeader* def, int* model, f32* mtxA, f32* mtxB)
{
    void* cache;
    int count;
    int i;
    MtxPtr mid;
    MtxPtr dstB;
    MtxPtr dstA;
    f32 fill;

    cache = getCache();
    count = (s32)(u32)def->jointCount + (s32)(u32)def->extraJointCount;
    dstA = (MtxPtr)((u8*)cache + 0x2700);
    mid = (MtxPtr)cache;
    dstB = (MtxPtr)((u8*)cache + 0x12c0);
    cacheQueueWait(0);
    i = 0;
    fill = 0.0f;
    for (; i < count; i++)
    {
        PSMTXConcat((MtxPtr)mtxA, dstA, mid);
        PSMTXConcat(mid, (MtxPtr)mtxB, dstB);
        dstB[0][3] = fill;
        dstB[1][3] = fill;
        dstB[2][3] = fill;
        dstA += 4;
        mid += 3;
        dstB += 3;
    }
    gModelMtxCacheState = 2;
}

void modelCalcVtxGroupMtxs(ModelFileHeader* def, ObjModel* model)
{
    Mtx ma;
    Mtx mb;
    Mtx trans;
    int off;
    int i;
    ModelFileHeader* modelDef;
    u8* modelBytes;

    modelDef = def;
    modelBytes = (u8*)model;

    for (i = 0, off = 0; i < modelDef->extraJointCount; i++)
    {
        MtxPtr out;
        MtxPtr m2;
        MtxPtr m1;
        ModelBone* jd;
        u8* grp;
        f32 w;
        f32 wi;

        grp = modelDef->extraJointDefs + off;
        out = (MtxPtr)ObjModel_GetJointMatrix(modelBytes, i + modelDef->jointCount);
        m1 = (MtxPtr)ObjModel_GetJointMatrix(modelBytes, grp[0]);
        m2 = (MtxPtr)ObjModel_GetJointMatrix(modelBytes, grp[1]);

        w = (f32)grp[2] / 4.0f;
        wi = 1.0f - w;

        jd = (ModelBone*)((char*)modelDef->jointData + grp[0] * 0x1c);
        PSMTXTrans(trans, -jd->tail[0], -jd->tail[1], -jd->tail[2]);
        PSMTXConcat(m1, trans, ma);
        jd = (ModelBone*)((char*)modelDef->jointData + grp[1] * 0x1c);
        PSMTXTrans(trans, -jd->tail[0], -jd->tail[1], -jd->tail[2]);
        PSMTXConcat(m2, trans, mb);

        out[0][0] = ma[0][0] * w + mb[0][0] * wi;
        out[0][1] = ma[0][1] * w + mb[0][1] * wi;
        out[0][2] = ma[0][2] * w + mb[0][2] * wi;
        out[0][3] = ma[0][3] * w + mb[0][3] * wi;
        out[1][0] = ma[1][0] * w + mb[1][0] * wi;
        out[1][1] = ma[1][1] * w + mb[1][1] * wi;
        out[1][2] = ma[1][2] * w + mb[1][2] * wi;
        out[1][3] = ma[1][3] * w + mb[1][3] * wi;
        out[2][0] = ma[2][0] * w + mb[2][0] * wi;
        out[2][1] = ma[2][1] * w + mb[2][1] * wi;
        out[2][2] = ma[2][2] * w + mb[2][2] * wi;
        out[2][3] = ma[2][3] * w + mb[2][3] * wi;
        off += 4;
    }
}


void modelInitMtxs(ModelFileHeader* def, ObjModel* model)
{
    u8* cache;
    u8* mtx;
    int count;
    u8 rem;

    cache = (u8*)getCache();
    if (def->extraJointCount != 0)
    {
        modelCalcVtxGroupMtxs(def, model);
    }
    count = (s32)(u32)def->jointCount + (s32)(u32)def->extraJointCount;
    if (count >= 2 && count <= 0x64)
    {
        mtx = (u8*)ObjModel_GetJointMatrix((u8*)model, 0);
        DCFlushRange((void*)mtx, count << 6);
        rem = (u8)(count << 1);
        cache += 0x2700;
        while (rem >= 0x80)
        {
            copyToCache((void*)cache, (void*)mtx, 0);
            rem -= 0x80;
            mtx += 0x1000;
            cache += 0x1000;
        }
        if (rem != 0)
        {
            copyToCache((void*)cache, (void*)mtx, rem);
        }
        gModelMtxCacheState = 1;
    }
    else
    {
        gModelMtxCacheState = 3;
    }
}


const IndTexMtx23 sObjFuzzIndMtxA = {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sObjFuzzIndMtxB = {{{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};
const IndTexMtx23 sObjFuzzShellIndMtxA = {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sObjFuzzShellIndMtxB = {{{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};

extern u8 gObjFuzzPhaseLatched;

extern GXColor lbl_803DB470;
extern int lbl_803DB498;
extern int lbl_803DB49C;

int objFuzzShellRenderCb(GameObject* obj, int* model, int ropIdx)
{
    Mtx mtx4;
    Mtx mtx3;
    Mtx mtx2;
    Mtx mtxR;
    Mtx mtx5;
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    GXColor kc = sObjFuzzWhiteColor;
    Texture** noiseTextures;
    int noiseFrameCount;
    Texture* t164;
    f32 sx;
    f32 sy;
    GXColor kc2;
    Texture** shadowTable;
    int shadowStride;
    int shadowRows;
    Shader* rop;
    f32 fz;
    u8 v;

    mtxA = sObjFuzzShellIndMtxA;
    mtxB = sObjFuzzShellIndMtxB;
    rop = ObjModel_GetRenderOp(((ObjModel*)model)->file, ropIdx);
    if ((rop->flags & 0x200) == 0)
    {
        if ((gObjFuzzLayerIndex & 3) != 0)
        {
            gObjFuzzPassActive = 0;
            return 0;
        }
        gObjFuzzPassActive = 1;
        objFuzzSetupGxState(obj);
        return 1;
    }
    gObjFuzzPassActive = 1;
    getNewShadowNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
    fz = (f32)gObjFuzzLayerIndex / (f32)(s32)noiseFrameCount;
    fz = fz * fz;
    fz = fz / 2.0f;
    selectTexture((Texture*)(textureIdxToPtr(*(u32*)Shader_getLayer(rop, 0))), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    v = obj->sphereMapIntensity;
    kc.b = v;
    kc.g = v;
    kc.r = v;
    GXSetTevKColor(GX_KCOLOR0, kc);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    PSMTXScale(mtx3, -0.5f, -0.5f, 0.0f);
    PSMTXTrans(mtx2, 0.5f, 0.5f, 1.0f);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTTEXMTX1);
    selectTexture((Texture*)(ObjModel_GetRenderOpTextureRefs((ObjModel*)model, ropIdx)->texture0), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getNewShadowCausticTexture((u32*)&t164);
    selectTexture(t164, 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, 0.5f * sx, 0.5f * sy, 0.0f);
    mtxR[0][0] = 1.0f;
    mtxR[1][1] = 1.0f;
    GXLoadTexMtxImm(mtxR, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP4);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    mtxA.m[0][0] = fz;
    mtxA.m[1][1] = fz;
    GXSetIndTexMtx(GX_ITM_0, mtxA.m, (s8)lbl_803DB498);
    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    selectTexture((Texture*)(textureIdxToPtr(rop->indTextureId)), 2);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    mtxB.m[0][1] = fz;
    mtxB.m[1][2] = fz;
    GXSetIndTexMtx(GX_ITM_1, mtxB.m, (s8)lbl_803DB49C);
    GXSetTevIndirect(GX_TEVSTAGE3, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_S);
    selectTexture(noiseTextures[gObjFuzzLayerIndex], 3);
    PSMTXScale(mtx4, 37.5f, 37.5f, 1.0f);
    GXLoadTexMtxImm(mtx4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX0);
    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD4, GX_TEXMAP3, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (gObjFuzzLayerIndex < 0xc)
    {
        GXSetNumTevStages(4);
        GXSetNumIndStages(2);
        GXSetNumTexGens(5);
    }
    else
    {
        ModelLightStruct* lt;
        kc2 = sObjFuzzDirLightEnvColor;
        lt = objCreateLight(obj, 0);
        if (lt != NULL)
        {
            modelLightStruct_setLightKind(lt, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setDirection(lt, 0.0f, -0.707f, 0.0f);
            modelLightStruct_setDiffuseColor(lt, 0xff, 0xff, 0xff, 0xff);
            modelLightChannels_reset(0);
            modelLightChannel_configure(2, 0, 0);
            GXSetChanAmbColor(GX_ALPHA0, lbl_803DB470);
            GXSetChanMatColor(GX_ALPHA0, lbl_803DB468);
            modelLightStruct_loadChannelLight(2, lt, obj);
            modelLightChannels_applyGXControls();
            ModelLightStruct_free(lt);
        }
        GXSetTevKColor(GX_KCOLOR0, kc2);
        GXSetTevKAlphaSel(GX_TEVSTAGE5, GX_TEV_KASEL_K0_A);
        GXSetTevKColorSel(GX_TEVSTAGE5, GX_TEV_KCSEL_K0);
        newshadows_getShadowTextureTable4x8(&shadowTable, &shadowStride, &shadowRows);
        selectTexture(shadowTable[(gObjFuzzLayerIndex - 0xc) + gObjFuzzPhaseLatched * shadowStride], 5);
        PSMTXScale(mtx5, 20.0f, 20.0f, 1.0f);
        GXLoadTexMtxImm(mtx5, GX_PTTEXMTX3, GX_MTX3x4);
        GXSetTexCoordGen2(GX_TEXCOORD5, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX3);
        GXSetTevDirect(GX_TEVSTAGE4);
        GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD5, GX_TEXMAP5, GX_COLOR0A0);
        GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevDirect(GX_TEVSTAGE5);
        GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_CPREV, GX_CC_KONST, GX_CC_A1, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_APREV, GX_CA_A1, GX_CA_A1, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(6);
        GXSetNumIndStages(2);
        GXSetNumTexGens(6);
    }
    GXSetCullMode(GX_CULL_BACK);
    {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}

extern GXColor gObjFuzzKColor;
extern u8 lbl_803DCC35;
extern u8 lbl_803DCC36;
extern s32 gObjSelectedLightCount;
extern u8 gObjProjectedLightChannel;
extern int lbl_803DB48C;
extern int lbl_803DB490;

static inline int shaderProjDisabled(ModelLightStruct* light)
{
    int flag;
    int mode;
    modelLightStruct_getProjectionTevModes(light, &flag, &mode);
    return flag;
}

int objFuzzRenderCb(GameObject* obj, ObjModel* model, int ropIdx)
{
    Mtx mtx4;
    Mtx mtx3;
    Mtx mtx2;
    Mtx mtxR;
    IndTexMtx23 mtxA;
    IndTexMtx23 mtxB;
    GXColorS10 s10 = sObjFuzzWhiteColorS10;
    int stage;
    int coord;
    Texture** noiseTextures;
    int noiseFrameCount;
    Texture* texRef4;
    f32 sx;
    f32 sy;
    int projFlagOut1;
    Shader* rop;
    f32 fz;
    int projBlendMode;
    u8 fancy;

    mtxA = sObjFuzzIndMtxA;
    mtxB = sObjFuzzIndMtxB;
    rop = ObjModel_GetRenderOp(model->file, ropIdx);
    if ((rop->flags & 0x200) == 0)
    {
        gObjFuzzPassActive = 0;
        return 0;
    }
    gObjFuzzPassActive = 1;
    getNewShadowNoiseTextureFrames(&noiseTextures, &noiseFrameCount);
    if (lbl_803DCC35 != 0)
    {
        fz = 0.0f;
    }
    else
    {
        fz = (f32)gObjFuzzLayerIndex / (f32)(s32)noiseFrameCount;
        fz = fz / 2.0f;
    }
    selectTexture((Texture*)(textureIdxToPtr(*(u32*)Shader_getLayer(rop, 0))), 0);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    if (lbl_803DCC36 == 0)
    {
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    }
    else
    {
        if (lbl_803DCC36 == 1)
        {
            u8 v = gObjFuzzLayerIndex << 4;
            gObjFuzzKColor.b = v;
            gObjFuzzKColor.g = v;
            gObjFuzzKColor.r = v;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ONE, GX_CC_KONST, GX_CC_ZERO);
        }
        else
        {
            if (gObjFuzzLayerIndex < 8)
            {
                gObjFuzzKColor.b = gObjFuzzLayerIndex << 5;
            }
            else
            {
                gObjFuzzKColor.b = 0xff;
            }
            gObjFuzzKColor.g = gObjFuzzKColor.b;
            gObjFuzzKColor.r = gObjFuzzKColor.b;
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_ZERO, GX_CC_KONST, GX_CC_ZERO);
        }
        GXSetTevKColor(GX_KCOLOR1, *(GXColor*)&gObjFuzzKColor);
        GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K1_A);
        GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K1);
    }
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    {
        u8 v = obj->sphereMapIntensity;
        s10.b = v;
        s10.g = v;
        s10.r = v;
        s10.a = obj->anim.renderAlpha - 0xff;
    }
    GXSetTevColorS10(GX_TEVREG2, s10);
    PSMTXScale(mtx3, -0.5f, -0.5f, 0.0f);
    PSMTXTrans(mtx2, 0.5f, 0.5f, 1.0f);
    PSMTXConcat(mtx2, mtx3, mtx3);
    GXLoadTexMtxImm(mtx3, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTTEXMTX1);
    selectTexture((Texture*)(ObjModel_GetRenderOpTextureRefs(model, ropIdx)->texture0), 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR0A0);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C2, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    if (gObjSelectedLightCount != 0 && shaderProjDisabled(gObjSelectedLights) == 0)
    {
        fancy = 1;
    }
    else
    {
        fancy = 0;
    }
    if (fancy)
    {
        GXSetTevDirect(GX_TEVSTAGE2);
        GXLoadTexMtxImm((MtxPtr)modelLightStruct_getProjectionTexMtx(gObjSelectedLights), GX_PTTEXMTX3, GX_MTX3x4);
        GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, GX_PTTEXMTX3);
        if (gObjProjectedLightChannel == 0 || gObjProjectedLightChannel == 2)
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR0A0);
        }
        else
        {
            GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD1, GX_TEXMAP5, GX_COLOR1A1);
        }
        selectTexture((Texture*)(modelLightStruct_getProjectionTexture(gObjSelectedLights)), 5);
        modelLightStruct_getProjectionTevModes(gObjSelectedLights, &projFlagOut1, &projBlendMode);
        if (projBlendMode == 2)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_C1, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (projBlendMode == 3)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_C1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (projBlendMode == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1);
        }
        else if (gObjProjectedLightChannel == 0 || gObjProjectedLightChannel == 1)
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_C1);
        }
        else
        {
            GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, GX_CC_C1);
        }
        GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        if (projBlendMode == 1)
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        else
        {
            GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        stage = 3;
        coord = 5;
    }
    else
    {
        stage = 2;
        coord = 1;
    }
    getNewShadowCausticTexture((u32*)&texRef4);
    selectTexture(texRef4, 4);
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtxR, 0.5f * sx, 0.5f * sy, 0.0f);
    mtxR[0][0] = 1.0f;
    mtxR[1][1] = 1.0f;
    GXLoadTexMtxImm(mtxR, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(coord, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, coord, GX_TEXMAP4);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    mtxA.m[0][0] = fz;
    mtxA.m[1][1] = fz;
    GXSetIndTexMtx(GX_ITM_0, mtxA.m, (s8)lbl_803DB48C);
    GXSetTevIndirect(stage, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
    GXSetTevOrder(stage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(stage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(stage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(stage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(stage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    if (rop->indTexture != NULL)
    {
        selectTexture((Texture*)(textureIdxToPtr(rop->indTextureId)), 2);
        GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
        mtxB.m[0][1] = fz;
        mtxB.m[1][2] = fz;
        GXSetIndTexMtx(GX_ITM_1, mtxB.m, (s8)lbl_803DB490);
        GXSetTevIndirect(stage + 1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_S);
    }
    else
    {
        GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD3, GX_TEXMAP2);
        GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
        mtxB.m[0][1] = 0.0f;
        mtxB.m[1][2] = 0.0f;
        GXSetIndTexMtx(GX_ITM_1, mtxB.m, -0xf);
        GXSetTevIndirect(stage + 1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    }
    selectTexture(noiseTextures[gObjFuzzLayerIndex], 3);
    PSMTXScale(mtx4, 37.5f, 37.5f, 1.0f);
    GXLoadTexMtxImm(mtx4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX0);
    GXSetTevKColorSel(stage + 1, GX_TEV_KCSEL_1_2);
    if (rop->indTexture != NULL)
    {
        GXSetTevOrder(stage + 1, GX_TEXCOORD4, GX_TEXMAP3, GX_ALPHA_BUMPN);
        GXSetTevAlphaIn(stage + 1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_APREV);
    }
    else
    {
        GXSetTevOrder(stage + 1, GX_TEXCOORD4, GX_TEXMAP3, GX_COLOR_NULL);
        GXSetTevAlphaIn(stage + 1, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    }
    GXSetTevColorIn(stage + 1, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevSwapMode(stage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(stage + 1, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (fancy)
    {
        GXSetNumTevStages(5);
        GXSetNumTexGens(6);
    }
    else
    {
        GXSetNumTevStages(4);
        GXSetNumTexGens(5);
    }
    GXSetNumIndStages(2);
    GXSetCullMode(GX_CULL_BACK);
    if ((model->file->flags & 0x100) != 0)
    {
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
    }
    else
    {
        _gxSetFogParams();
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return 1;
}

u32 lbl_803DCC6C;
u32 lbl_803DCC68;

ModelLightStruct* gObjSelectedLights;
u8 gObjProjectedLightChannel;
s32 gObjSelectedLightCount;
u8 gObjOverrideColor[3];
GXColor gObjCurChanColor;
f32 gObjShadowDist;
u8 gObjShadowNear;
s32 gModelMtxCacheState;
s32 gObjFuzzLayerIndex;
s32 gObjFuzzStep;
u8 gObjFuzzPassActive;
u8 gObjFuzzPhaseLatched;
u8 gObjAlphaCompareThreshold;
f32 gObjFuzzPhase;
u8 lbl_803DCC36;
u8 lbl_803DCC35;
u8 lbl_803DCC34;
u32 gObjCachedModel;
u32 gObjCachedTexture;
u8 gObjRenderSetupDone;
u8 gObjRenderingShadowPass;
u8 gObjOverrideColorPending;
MtxPtr curObjMtx;
u8 lbl_803DCC20;

GXColor lbl_803DB468 = {0xFF, 0xFF, 0xFF, 0xFF};
u32 gObjGxDefaultChanColor = 0xFF;
GXColor lbl_803DB470 = {0, 0, 0, 0};
u32 gObjGxVtxDescCache = 0xFFFFFFFF;
u8 gObjGxBlendModeCache = 0xFF;
u8 gObjGxZCompLocCache = 0xFF;
u32 gObjGxAlphaCompareCache = 0xFFFFFFFF;
u8 gObjGxZWriteCache = 0xFF;
u8 gObjGxZCompareCache = 0xFF;
u8 gObjGxCullModeCache = 0xFF;
u8 gObjGxKColorCache[4] = {0};
u8 gObjShadowColor[4] = {0x20, 0x30, 0xFF, 0xFF};
int lbl_803DB48C = -1;
int lbl_803DB490 = -1;
GXColor gObjFuzzKColor = {0xFF, 0xFF, 0xFF, 0xFF};
int lbl_803DB498 = -3;
int lbl_803DB49C = -1;


#define OBJPRINT_MODEL_DEF(obj)         (((ObjAnimComponent*)(obj))->modelInstance)


void objFuzzSetupGxState(void* objArg)
{
    ModelLightStruct* renderHandle;
    void* obj = objArg;
    GXColor savedEnvColor = sObjFuzzSavedEnvColor;
    Texture** shadowTable;
    int shadowStride;
    int shadowParam;
    float mtx[12];

    renderHandle = objCreateLight((void*)obj, '\0');
    if (renderHandle != 0x0)
    {
        modelLightStruct_setLightKind(renderHandle, MODEL_LIGHT_KIND_DIRECTIONAL);
        modelLightStruct_setDirection(renderHandle, 0.0f, -0.707f, 0.0f);
        modelLightStruct_setDiffuseColor(renderHandle, 0xff, 0xff, 0xff, 0xff);
        modelLightChannels_reset(0);
        modelLightChannel_configure(2, 0, 0);
        GXSetChanAmbColor(GX_ALPHA0, lbl_803DB470);
        GXSetChanMatColor(GX_ALPHA0, lbl_803DB468);
        modelLightStruct_loadChannelLight(2, renderHandle, (GameObject*)obj);
        modelLightChannels_applyGXControls();
        ModelLightStruct_free(renderHandle);
    }
    GXSetTevKColor(GX_KCOLOR0, savedEnvColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    newshadows_getShadowTextureTable4x8(&shadowTable, &shadowStride, &shadowParam);
    selectTexture(shadowTable[(gObjFuzzLayerIndex >> 2) + gObjFuzzPhaseLatched * shadowStride], 0);
    PSMTXScale((MtxPtr)mtx, 20.0f, 20.0f, 1.0f);
    GXLoadTexMtxImm((const f32 (*)[4])mtx, 0x40, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_TRUE, GX_PTTEXMTX0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD1, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(2);
    GXSetCullMode(GX_CULL_BACK);
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    return;
}



extern PPCWGPipe GXWGFifo : (0xCC008000);

extern u8 gObjGxPosMtxIdTable[12];

void objRenderAttachment(GameObject* obj, int* p2)
{
    f32 wm[16];
    f32 cm[16];
    f32 sm[12];
    MatrixTransform blk;
    int* mdl = p2;
    u8* data = (u8*)((ObjModel*)mdl)->renderAttachment;
    s16 b;
    s16 c;
    u16* idx;
    int off;
    s16* v;
    int i;
    s16* verts;
    s16* uvs;
    u8* tri;
    s16 a;
    s16* uv;
    f32* vm = Camera_GetViewMatrix();
    Obj_BuildWorldTransformMatrix(obj, wm, 0);
    PSMTXConcat((MtxPtr)vm, (MtxPtr)wm, (MtxPtr)cm);
    GXLoadPosMtxImm((const f32 (*)[4])cm, gObjGxPosMtxIdTable[0]);
    GXSetCurrentMtx(gObjGxPosMtxIdTable[0]);
    PSMTXScale((MtxPtr)sm, 1.0f / obj->anim.rootMotionScale,
               1.0f / obj->anim.rootMotionScale, 1.0f);
    cm[3] = 0.0f;
    cm[7] = 0.0f;
    cm[11] = 0.0f;
    PSMTXConcat((MtxPtr)cm, (MtxPtr)sm, (MtxPtr)cm);
    GXLoadTexMtxImm((const f32 (*)[4])cm, 0x1e, GX_MTX3x4);
    objFrozenRenderCb(obj, (void**)mdl, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_NRM, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    verts = *(s16**)(data + 4);
    uvs = *(s16**)(data + 8);
    GXBegin(GX_TRIANGLES, GX_VTXFMT7, *(u16*)(data + 0xc) * 3);
    {
        i = 0;
        off = 0;
        for (; i < *(u16*)(data + 0xc); i++)
        {
            int k;
            tri = *(u8**)data + off;
            idx = (u16*)tri;
            for (k = 0; k < 3; k++)
            {
                v = verts + *idx * 3;
                c = v[2];
                b = v[1];
                a = v[0];
                GXWGFifo.s16 = a;
                GXWGFifo.s16 = b;
                GXWGFifo.s16 = c;
                {
                    u8 b2;
                    u8 c2;
                    u8 a2;
                    c2 = tri[8];
                    b2 = tri[7];
                    a2 = tri[6];
                    GXWGFifo.u8 = a2;
                    GXWGFifo.u8 = b2;
                    GXWGFifo.u8 = c2;
                }
                uv = uvs + *idx * 2;
                b = uv[1];
                a = uv[0];
                GXWGFifo.s16 = a;
                GXWGFifo.s16 = b;
                idx++;
            }
            off += 0xa;
        }
    }
    GXSetCurrentMtx(0);
    if (randomGetRange(0, 5) == 0)
    {
        int m = randomGetRange(0, *(s16*)(data + 0xe) - 1) * 3;
        f32 fs = obj->anim.rootMotionScale;
        blk.x = fs * (f32)(verts[m] >> 8) + obj->anim.localPosX;
        blk.y = fs * (f32)(verts[m + 1] >> 8) + obj->anim.localPosY;
        blk.z = fs * (f32)(verts[m + 2] >> 8) + obj->anim.localPosZ;
        blk.scale = 1.0f;
        blk.rotX = 0;
        blk.rotZ = 0;
        blk.rotY = 0;
        (*gPartfxInterface)->spawnObject(obj, 0x7fd, &blk, 0x200001, -1, NULL);
    }
}

static void objSetupLightChannels(u8* model, GameObject* obj)
{
    int t2;
    int t10;
    int en2;
    int chan;
    u8 ch;
    u16 f;
    u8 b;
    ModelLightStruct* larr[6];
    s32 count;
    GXColor c;

    count = 0;
    gObjSelectedLightCount = 0;
    b = ((ModelFileHeader*)model)->flags24;
    t2 = b & 2;
    if (t2)
    {
        en2 = 1;
    }
    else
    {
        en2 = 0;
    }
    t10 = b & 0x10;
    chan = t10 ? 4 : 0;
    if (((ModelFileHeader*)model)->shaderFlags & 2)
    {
        if (t2 || t10)
        {
            gObjCurChanColor.a = 0;
            GXSetChanAmbColor((u8)chan, gObjCurChanColor);
            GXSetChanCtrl(GX_COLOR0, GX_TRUE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(1);
        }
        else
        {
            GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
        }
    }
    else
    {
        modelLightChannels_reset(0);
        ch = chan;
        modelLightChannel_configure(ch, 0, en2);
        f = ((ModelFileHeader*)model)->shaderFlags;
        if (!(f & 9))
        {
            int mode;
            if (f & 0xc)
            {
                mode = 2;
                GXSetChanAmbColor(ch, *(GXColor*)&gObjGxDefaultChanColor);
            }
            else
            {
                int l;
                mode = 6;
                l = OBJPRINT_MODEL_DEF(obj)->modelLightMaskIndex;
                if (l == 0)
                {
                    skyApplyLightSlot(obj->lightColorSlot);
                    skyGetAmbientColor(obj->lightColorSlot, &c.r, &c.g, &c.b);
                }
                else
                {
                    lightGetColor(l, &c.r, &c.g, &c.b);
                }
                c.a = 0;
                GXSetChanAmbColor(ch, c);
            }
            {
                u32 nl = obj->anim.modelInstance->maxLights;
                if (nl != 0)
                {
                    modelLightStruct_selectObjectLights(obj, larr, nl, &count, mode);
                }
            }
            if (count == 0)
            {
                GXSetChanMatColor(ch, *(GXColor*)&gObjGxDefaultChanColor);
            }
            else
            {
                GXSetChanMatColor(ch, lbl_803DB468);
            }
            {
                int i;
                ModelLightStruct** p;
                i = 0;
                p = larr;
                for (; i < count; i++)
                {
                    modelLightStruct_loadChannelLight(ch, *p, obj);
                    p++;
                }
            }
        }
        else
        {
            if (f & 1)
            {
                GXSetChanMatColor(chan & 0xff, lbl_803DB468);
            }
            else
            {
                GXSetChanMatColor(chan & 0xff, *(GXColor*)&gObjGxDefaultChanColor);
            }
        }
        {
            u32 nf = ((ModelFileHeader*)model)->texMtxCount;
            if (nf != 0)
            {
                modelLightStruct_selectObjectLights(obj, &gObjSelectedLights, nf, &gObjSelectedLightCount, 8);
                if ((OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) || gObjShadowNear)
                {
                    gObjSelectedLightCount = 0;
                }
                {
                    u8 got;
                    ModelLightStruct** lp;
                    u8* sp;
                    int k;
                    got = 0;
                    k = 0;
                    lp = &gObjSelectedLights;
                    sp = &gObjProjectedLightChannel;
                    for (; k < gObjSelectedLightCount; k++)
                    {
                        int t = modelLightStruct_getProjectedLightChannelPreference(*lp);
                        if (!got && t == 1)
                        {
                            *sp = 1;
                            got = 1;
                        }
                        else if (k == 0)
                        {
                            *sp = 2;
                        }
                        else
                        {
                            *sp = 3;
                        }
                        modelLightChannel_configure(*sp, 2, 0);
                        modelLightStruct_loadChannelLight(*sp, *lp, obj);
                        GXSetChanAmbColor(*sp, lbl_803DB470);
                        GXSetChanMatColor(*sp, lbl_803DB468);
                        lp++;
                        sp++;
                    }
                }
            }
        }
        modelLightChannels_applyGXControls();
        {
            u8 b5f = OBJPRINT_MODEL_DEF(obj)->renderFlags;
            if ((b5f & 4) || gObjShadowNear)
            {
                gObjSelectedLightCount = 2;
            }
            else if (b5f & 0x11)
            {
                gObjSelectedLightCount = 1;
            }
        }
    }
}



extern u8 gObjGxPosMtxIdTable[12];


static void modelLoadMtxsToGx(ModelFileHeader* hdr, int* model, MtxBitStream* bs, f32* mtx)
{
    char* cache = (char*)getCache();
    if (gModelMtxCacheState == 1)
    {
        char* cacheBase = (char*)getCache();
        char* sourceMtx;
        char* posMtx;
        int i;
        int count = hdr->jointCount + hdr->extraJointCount;
        sourceMtx = cacheBase + 0x2700;
        posMtx = cacheBase;
        cacheQueueWait(0);
        for (i = 0; i < count; i++)
        {
            PSMTXConcat((MtxPtr)mtx, (MtxPtr)(f32*)sourceMtx, (MtxPtr)(f32*)posMtx);
            sourceMtx += 0x40;
            posMtx += 0x30;
        }
        gModelMtxCacheState = 2;
    }
    {
        u8* posMtxIds[1];
        int i;
        int count;
        f32 tmp[12];
        {
            u32 w;
            int pos = bs->pos;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 4;
            count = (w >> (pos & 7)) & 0xf;
        }
        i = 0;
        posMtxIds[0] = gObjGxPosMtxIdTable;
        for (; i < count; i++)
        {
            int idx;
            {
                u32 w;
                int pos = bs->pos;
                u32 pAddr = (pos >> 3) + ((u32)bs->data + 1);
                w = *(u8*)(pAddr - 1);
                w |= *(u8*)pAddr << 8;
                w |= *(u8*)(pAddr + 1) << 16;
                bs->pos = pos + 8;
                idx = (w >> (pos & 7)) & 0xff;
            }
            if (gModelMtxCacheState == 2)
            {
                GXLoadPosMtxImm((const f32 (*)[4])(cache + idx * 0x30), *posMtxIds[0]);
            }
            else
            {
                PSMTXConcat((MtxPtr)mtx, (MtxPtr)(f32*)ObjModel_GetJointMatrix((u8*)model, idx), (MtxPtr)tmp);
                GXLoadPosMtxImm((const f32 (*)[4])tmp, *posMtxIds[0]);
            }
            posMtxIds[0]++;
        }
    }
}

static void renderOpMatrix(u8* hdr, int* model, MtxBitStream* bs, f32* m1, f32* mtx, u8 nrm, u8 tex, u8 skip)
{
    u8* posMtxIds[1];
    char* cache;
    posMtxIds[0] = gObjGxPosMtxIdTable;
    cache = (char*)getCache();
    if (gModelMtxCacheState == 1)
    {
        if (skip == 0)
        {
            modelBuildPosNrmMtxs((ModelFileHeader*)hdr, model, mtx, m1);
        }
        else
        {
            char* cacheBase = (char*)getCache();
            char* posMtx;
            int i;
            int total = hdr[0xf3] + hdr[0xf4];
            hdr = (u8*)(cacheBase + 0x2700);
            posMtx = cacheBase;
            cacheQueueWait(0);
            for (i = 0; i < total; i++)
            {
                PSMTXConcat((MtxPtr)mtx, (MtxPtr)(f32*)hdr, (MtxPtr)(f32*)posMtx);
                hdr += 0x40;
                posMtx += 0x30;
            }
            gModelMtxCacheState = 2;
        }
    }
    {
        u8* texMtxIds;
        int i;
        int count;
        f32 tmp[12];
        {
            u32 w;
            int pos = bs->pos;
            int off = pos >> 3;
            u8* p;
            w = bs->data[off];
            p = (u8*)(off + (char*)bs->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs->pos = pos + 4;
            count = (w >> (pos & 7)) & 0xf;
        }
        if (count < 0 || count > 20)
        {
            OSReport((char*)&posMtxIds[0][0x48], count);
        }
        i = 0;
        texMtxIds = posMtxIds[0] + 0xc;
        for (; i < count; i++)
        {
            int idx;
            {
                u32 w;
                int pos = bs->pos;
                u32 pAddr = (pos >> 3) + ((u32)bs->data + 1);
                w = *(u8*)(pAddr - 1);
                w |= *(u8*)pAddr << 8;
                w |= *(u8*)(pAddr + 1) << 16;
                bs->pos = pos + 8;
                idx = (w >> (pos & 7)) & 0xff;
            }
            if (gModelMtxCacheState == 2)
            {
                u8* posMtx = (u8*)(cache + idx * 0x30);
                u8* normalMtx = posMtx + 0x12c0;
                GXLoadPosMtxImm((const f32 (*)[4])posMtx, *posMtxIds[0]);
                if (skip == 0 && tex != 0)
                {
                    GXLoadTexMtxImm((const f32 (*)[4])normalMtx, *texMtxIds, GX_MTX3x4);
                }
                if (skip == 0 && nrm != 0)
                {
                    GXLoadNrmMtxImm((const f32 (*)[4])normalMtx, *posMtxIds[0]);
                }
            }
            else
            {
                PSMTXConcat((MtxPtr)mtx, (MtxPtr)(f32*)ObjModel_GetJointMatrix((u8*)model, idx), (MtxPtr)tmp);
                GXLoadPosMtxImm((const f32 (*)[4])tmp, *posMtxIds[0]);
                if (skip == 0 && (nrm != 0 || tex != 0))
                {
                    tmp[3] = 0.0f;
                    tmp[7] = 0.0f;
                    tmp[11] = 0.0f;
                    PSMTXConcat((MtxPtr)tmp, (MtxPtr)m1, (MtxPtr)tmp);
                    if (tex != 0)
                    {
                        GXLoadTexMtxImm((const f32 (*)[4])tmp, *texMtxIds, GX_MTX3x4);
                    }
                    if (nrm != 0)
                    {
                        GXLoadNrmMtxImm((const f32 (*)[4])tmp, *posMtxIds[0]);
                    }
                }
            }
            posMtxIds[0]++;
            texMtxIds++;
        }
    }
}







static void objRenderShadowModel(GameObject* obj, GameObject* obj2, u8* m, int p4);
static void modelDoRenderInstrs(GameObject* obj, GameObject* obj2, u8* m, u8 passMask);
static void objRenderChild(GameObject* child, GameObject* parent, u8 isShadow);



#define OBJPRINT_MODEL_DEF(obj)         (((ObjAnimComponent*)(obj))->modelInstance)




extern u8 gObjGxPosMtxIdTable[12];


static void ModelHeader_setupPosTexFmt(u8* hdr, int* model, MtxBitStream* bs, int p4)
{
    u32 flags = 0;
    if (((ModelFileHeader*)hdr)->jointCount > 1)
    {
        flags |= 1;
    }
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        flags |= ((int)(w >> (pos & 7)) & 1) ? 2 : 0;
    }
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 1;
        flags |= ((int)(w >> (pos & 7)) & 1) ? 4 : 0;
    }
    if (gObjGxVtxDescCache != flags)
    {
        GXClearVtxDesc();
        if (flags & 1)
        {
            GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
        }
        else
        {
            GXSetCurrentMtx(gObjGxPosMtxIdTable[0]);
        }
        GXSetVtxDesc(GX_VA_POS, (flags & 2) ? GX_INDEX16 : GX_INDEX8);
        GXSetVtxDesc(GX_VA_TEX0, (flags & 4) ? GX_INDEX16 : GX_INDEX8);
        gObjGxVtxDescCache = flags;
    }
}

static void modelRenderFn_setVtxDescr(u8* modelHeader, u8* shader, u32* textureRefs,
                                      MtxBitStream* bitStream, u8 passMask,
                                      u8* usesNormalMatrix, u8* usesTextureMatrix)
{
    int nextMatrixAttr;
    int previousMatrixAttr;
    int textureCoordIndex;
    int textureIndex16;

    GXClearVtxDesc();
    if (((ModelFileHeader*)modelHeader)->jointCount > 1)
    {
        GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
        nextMatrixAttr = 1;
        previousMatrixAttr = 8;
        if (textureRefs[0] != 0 || textureRefs[1] != 0)
        {
            if (((Shader*)shader)->auxTexture != NULL)
            {
                GXSetVtxDesc(GX_VA_TEX0MTXIDX, GX_DIRECT);
                nextMatrixAttr = GX_VA_TEX1MTXIDX;
                GXSetVtxDesc(nextMatrixAttr++, GX_DIRECT);
            }
            GXSetVtxDesc(nextMatrixAttr++, GX_DIRECT);
        }
        {
            int i = 0;
            for (; i < ((ModelFileHeader*)modelHeader)->texMtxCount; i++)
            {
                u8 useForwardAttr;
                if (passMask == 4 && i == 0)
                {
                    int projectionModeB;
                    int projectionModeA;
                    if (gObjSelectedLightCount != 0 &&
                        (modelLightStruct_getProjectionTevModes(
                             gObjSelectedLights, &projectionModeA, &projectionModeB),
                         projectionModeA == 0))
                    {
                        useForwardAttr = 1;
                    }
                    else
                    {
                        useForwardAttr = 0;
                    }
                }
                else if (i < gObjSelectedLightCount && passMask == 0)
                {
                    useForwardAttr = 1;
                }
                else
                {
                    useForwardAttr = 0;
                }
                if (useForwardAttr)
                {
                    GXSetVtxDesc(nextMatrixAttr++, GX_DIRECT);
                }
                else
                {
                    GXSetVtxDesc(previousMatrixAttr--, GX_DIRECT);
                }
            }
        }
        if (nextMatrixAttr > 1)
        {
            *usesTextureMatrix = 1;
        }
        else
        {
            *usesTextureMatrix = 0;
        }
    }
    else
    {
        GXSetCurrentMtx(0);
        *usesTextureMatrix = 1;
    }
    {
        u32 w;
        int pos = bitStream->pos;
        int off = pos >> 3;
        u8* p;
        w = bitStream->data[off];
        p = (u8*)(off + (char*)bitStream->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bitStream->pos = pos + 1;
        GXSetVtxDesc(GX_VA_POS, (((int)(w >> (pos & 7)) & 1) ? GX_INDEX16 : GX_INDEX8));
    }
    if (((Shader*)shader)->vtxAttrFlags & 1)
    {
        int index16;
        {
            u32 w;
            int pos = bitStream->pos;
            int off = pos >> 3;
            u8* p;
            w = bitStream->data[off];
            p = (u8*)(off + (char*)bitStream->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bitStream->pos = pos + 1;
            index16 = (w >> (pos & 7)) & 1;
        }
        if (((ModelFileHeader*)modelHeader)->flags24 & 8)
        {
            GXSetVtxDesc(GX_VA_NBT, index16 ? GX_INDEX16 : GX_INDEX8);
        }
        else
        {
            GXSetVtxDesc(GX_VA_NRM, index16 ? GX_INDEX16 : GX_INDEX8);
        }
        *usesNormalMatrix = 1;
    }
    else
    {
        *usesNormalMatrix = 0;
    }
    if (((Shader*)shader)->vtxAttrFlags & 2)
    {
        u32 w;
        int pos = bitStream->pos;
        int off = pos >> 3;
        u8* p;
        w = bitStream->data[off];
        p = (u8*)(off + (char*)bitStream->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bitStream->pos = pos + 1;
        GXSetVtxDesc(GX_VA_CLR0, (((int)(w >> (pos & 7)) & 1) ? GX_INDEX16 : GX_INDEX8));
    }
    {
        {
            u32 w;
            int pos = bitStream->pos;
            int off = pos >> 3;
            u8* p;
            w = bitStream->data[off];
            p = (u8*)(off + (char*)bitStream->data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bitStream->pos = pos + 1;
            textureIndex16 = (w >> (pos & 7)) & 1;
        }
        textureCoordIndex = 0;
        for (; textureCoordIndex < ((Shader*)shader)->layerCount; textureCoordIndex++)
        {
            GXSetVtxDesc(textureCoordIndex + GX_VA_TEX0, textureIndex16 ? GX_INDEX16 : GX_INDEX8);
        }
    }
}
static inline void texSlotGetScroll(GameObject* obj, u32 jid, f32* txp, f32* typ)
{
    ObjTextureRuntimeSlot* slots = obj->anim.textureSlots;
    ObjDef* modelDef = obj->anim.modelInstance;
    ObjTextureSlotDef* q = modelDef->textureSlotDefs;
    int n = modelDef->textureSlotCount;
    int k;
    for (k = 0; k < n; k++)
    {
        if ((int)jid == q->materialIndex)
        {
            *txp = 0.0001f * slots[k].offsetS;
            *typ = 0.0001f * slots[k].offsetT;
            return;
        }
        q++;
    }
    *typ = *txp = 0.0f;
}
static u8 addShaderLayerStages(GameObject* obj, u8* shader, u32* p3, int mask, int p5, int p6)
{
    u16 alpha;
    u8* colp;
    void* tex;
    u8* prev;
    u8* layer;
    u8 ok;
    int layerIdx;
    u8 color[4];
    f32 m[12];

    ok = 1;
    if (p3[0] != 0 || p3[1] != 0)
    {
        int i;
        u8 cnt;
        cnt = 0;
        for (i = 0; i < ((Shader*)shader)->layerCount; i++)
        {
            ShaderLayer* l = Shader_getLayer(shader, i);
            if (l->typeBits & 0x80)
            {
                cnt++;
            }
        }
        if (cnt > 1)
        {
            ok = 0;
        }
    }
    layerIdx = 0;
    colp = &gObjCurChanColor.r;
    {
        for (; layerIdx < ((Shader*)shader)->layerCount; layerIdx++)
        {
            layer = Shader_getLayer(shader, layerIdx);
            if ((layer[4] & 0x80) == mask)
            {
                if ((((Shader*)shader)->flags & SHADER_FLAG_DECAL_LAYER) && layerIdx == 1)
                {
                    u8 hasBaseTexture;
                    if (p3[0] != 0)
                    {
                        hasBaseTexture = 1;
                    }
                    else
                    {
                        hasBaseTexture = 0;
                    }
                    addLitColorStage(hasBaseTexture);
                    return 1;
                }
                alpha = ((obj->anim.renderAlpha + 1) * ((Shader*)shader)->alpha) >> 8;
                if (*(u32*)layer != 0)
                {
                    f32 (*mtxp)[4];
                    u8 fl;
                    tex = textureIdxToPtr(*(u32*)layer);
                    {
                        u32 jid = layer[5];
                        if (jid != 0)
                        {
                            ObjTextureRuntimeSlot* slots = obj->anim.textureSlots;
                            ObjDef* modelDef = obj->anim.modelInstance;
                            ObjTextureSlotDef* q = modelDef->textureSlotDefs;
                            int n = modelDef->textureSlotCount;
                            int k;
                            for (k = 0; k < n; k++)
                            {
                                if ((int)jid == q->materialIndex)
                                {
                                    tex = textureGetAnimationFrame(tex, slots[k].textureId);
                                    break;
                                }
                                q++;
                            }
                            {
                                f32 tx;
                                f32 ty;
                                texSlotGetScroll(obj, layer[5], &tx, &ty);
                                PSMTXTrans((MtxPtr)m, tx, ty, 0.0f);
                                mtxp = (f32 (*)[4])m;
                            }
                        }
                        else
                        {
                            mtxp = NULL;
                        }
                    }
                    if (layerIdx == 0)
                    {
                        if ((p3[0] != 0 || p3[1] != 0 || p6 != 0) && ok)
                        {
                            fl = 8;
                        }
                        else
                        {
                            fl = 0;
                        }
                        color[3] = alpha;
                    }
                    else
                    {
                        fl = prev[4] & 0x7f;
                        color[3] = 0xff;
                    }
                    color[0] = 0xff;
                    color[1] = 0xff;
                    color[2] = 0xff;
                    if (p3[0] != 0 || (shader[0] == 0xff && shader[1] == 0xff && shader[2] == 0xff))
                    {
                        addTexLayerStageSwizzled(tex, mtxp, (u8)fl, (GXColor*)color, *((u8*)p3 + 8), 1);
                    }
                    else if (p5 != 0)
                    {
                        colp[3] = color[3];
                        if (((Shader*)shader)->vtxAttrFlags & 0x10)
                        {
                            addTexLayerStageKColor(tex, mtxp, (u8)fl, &gObjCurChanColor);
                        }
                        else
                        {
                            addTexLayerStageSwizzled(tex, mtxp, (u8)fl, &gObjCurChanColor, *((u8*)p3 + 8), 1);
                        }
                    }
                    else
                    {
                        if (((Shader*)shader)->vtxAttrFlags & 0x10)
                        {
                            addTexLayerStage(tex, mtxp, (u8)fl);
                            if (color[3] < 0xff)
                            {
                                addKColorModulateStage((GXColor*)color);
                            }
                        }
                        else
                        {
                            addTexLayerStageKAlpha(tex, mtxp, (u8)fl, (GXColor*)color);
                        }
                    }
                }
                else
                {
                    color[0] = shader[4];
                    color[1] = shader[5];
                    color[2] = shader[6];
                    color[3] = alpha;
                    if (p3[0] != 0 || (shader[0] == 0xff && shader[1] == 0xff && shader[2] == 0xff))
                    {
                        addKColorModulateStage((GXColor*)color);
                    }
                    else if (p5 != 0)
                    {
                        colp[3] = alpha;
                        addKColorModulateStage(&gObjCurChanColor);
                    }
                    else
                    {
                        if (((Shader*)shader)->vtxAttrFlags & 0x10)
                        {
                            addVertexColorStage();
                            if (color[3] < 0xff)
                            {
                                addKColorModulateStage((GXColor*)color);
                            }
                        }
                        else
                        {
                            addVertexColorKAlphaStage((GXColor*)color);
                        }
                    }
                }
            }
            prev = layer;
        }
    }
    return ok;
}
static u32 objSetupRenderOpGxState(GameObject* obj, u8* p2, int* am, MtxBitStream* bs)
{
    Shader* op;
    u32* refs;
    u32 idx;
    u8 shad;
    ModelLightStruct** lp;
    int envtex;
    int nlay;
    u8* sp;
    int i;
    ObjModelRenderCb cb;
    f32 m2[12];
    f32 t2[12];
    f32 wm[12];
    f32 t1[12];
    int a;
    int b;
    u8 color[4];
    u8 fogc[4];

    shad = 0;
    {
        u32 w;
        int pos = bs->pos;
        int off = pos >> 3;
        u8* p;
        w = bs->data[off];
        p = (u8*)(off + (char*)bs->data);
        w |= p[1] << 8;
        w |= p[2] << 16;
        bs->pos = pos + 6;
        idx = (w >> (pos & 7)) & 0x3f;
    }
    cb = (ObjModelRenderCb)ObjModel_GetRenderCallback((ObjModel*)am);
    if (cb != NULL && cb((int*)obj, am, idx) != 0)
    {
        return idx;
    }
    op = ObjModel_GetRenderOp((ModelFileHeader*)*am, idx);
    refs = (u32*)ObjModel_GetRenderOpTextureRefs((ObjModel*)am, idx);
    Rcp_ResetTextureStageState();
    envtex = 0;
    if ((refs[0] != 0 || refs[1] != 0) && op->auxTextureIndex != 0)
    {
        void* t = textureIdxToPtr(op->auxTextureIndex);
        int nl = gObjSelectedLightCount + 1;
        if (refs[0] != 0)
        {
            nl += 1;
        }
        if (refs[1] != 0)
        {
            nl += 1;
        }
        envtex = addEnvMapBumpStages(t, nl, op->envMapParams, op->layers[0].textureIndex);
        envtex &= 0xff;
    }
    if (refs[0] != 0)
    {
        addSphereMapTexStage((void*)refs[0], obj->sphereMapIntensity);
    }
    if (refs[1] != 0)
    {
        if (op->unk1C != 0)
        {
            color[0] = 0xff;
            color[1] = 0xff;
            color[2] = 0xff;
            color[3] = op->reg2Alpha;
        }
        else
        {
            color[3] = 0;
        }
        GXSetTevColor(GX_TEVREG2, *(GXColor*)color);
        {
            u8 hasBaseTexture;
            if (refs[0] != 0)
            {
                hasBaseTexture = 1;
            }
            else
            {
                hasBaseTexture = 0;
            }
            addLightTexReg2Stage((void*)refs[1], hasBaseTexture, op->reg2TexSlot);
        }
        if (color[3] != 0)
        {
            u8 hasBaseTexture;
            if (refs[0] != 0)
            {
                hasBaseTexture = 1;
            }
            else
            {
                hasBaseTexture = 0;
            }
            addAlphaLitColorReg2Stage(hasBaseTexture);
        }
    }
    else
    {
        GXSetTevColor(GX_TEVREG2, *(GXColor*)&gObjGxDefaultChanColor);
    }
    nlay = gObjSelectedLightCount;
    if (gObjShadowNear != 0)
    {
        addShadowFalloffTevStages();
        shad = 1;
        nlay = 0;
    }
    else
    {
        int b4;
        f32* mx;
        u8 b5f = OBJPRINT_MODEL_DEF(obj)->renderFlags;
        b4 = b5f & 4;
        if (b4 && (mx = (f32*)obj->anim.modelState->shadowCastSlot) != NULL)
        {
            addCastShadowTevStages((u8*)mx);
            nlay = 0;
        }
        else if (b5f & 0x10)
        {
            addWavyCausticTevStage();
            nlay = 0;
        }
        else if (b4 == 0)
        {
            i = 0;
            lp = &gObjSelectedLights;
            sp = &gObjProjectedLightChannel;
            for (; i < gObjSelectedLightCount; i++)
            {
                u8* t = (u8*)modelLightStruct_getProjectionTexture(*lp);
                if (t != 0)
                {
                    modelLightStruct_getProjectionTevModes(*lp, &a, &b);
                    if (a == 2)
                    {
                        shad = 1;
                    }
                    {
                        f32* mtx = modelLightStruct_getProjectionTexMtx(*lp);
                        addProjectedLightTevStage(t, mtx, a, b, *sp);
                    }
                }
                lp++;
                sp++;
            }
        }
    }
    if (envtex != 0)
    {
        addEnvMapTexCoord(envtex);
    }
    {
        u32 t18;
        if ((t18 = op->textureId) != 0 && op->unk1C == 0 && refs[1] != 0)
        {
            textureIdxToPtr(t18);
            addTexModulateReg2Stage();
        }
    }
    {
        u8 hl;
        if (addShaderLayerStages(obj, (u8*)op, refs, 0x80, hl = ((((ModelFileHeader*)p2)->shaderFlags & 2) && !(((ModelFileHeader*)p2)->flags24 & 2)),
                                   nlay) == 0)
        {
            u8 hasBaseTexture;
            if (refs[0] != 0)
            {
                hasBaseTexture = 1;
            }
            else
            {
                hasBaseTexture = 0;
            }
            addLitColorStage(hasBaseTexture);
        }
        if (op->flags & SHADER_FLAG_DECAL_LAYER)
        {
            u8* l1 = Shader_getLayer((u8*)op, 1);
            {
                f32 tx;
                f32 ty;
                texSlotGetScroll(obj, l1[5], &tx, &ty);
                PSMTXTrans((MtxPtr)m2, tx, ty, 0.0f);
            }
            addWarpedNoiseTevStages(textureIdxToPtr(*(u32*)l1), m2);
        }
        addShaderLayerStages(obj, (u8*)op, refs, 0, hl, nlay);
    }
    if (isHeavyFogEnabled() && !(((ModelFileHeader*)p2)->flags & 0x100))
    {
        getFogColorRgb(fogc);
        renderHeavyFog(fogc);
    }
    if (op->flags & SHADER_FLAG_PROJECTED_TEX_PASS)
    {
        f32* vm = Camera_GetViewMatrix();
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
        PSMTXConcat((MtxPtr)vm, (MtxPtr)wm, (MtxPtr)t1);
        PSMTXConcat((MtxPtr)(f32*)gCameraLightPerspectiveMatrix, (MtxPtr)t1, (MtxPtr)t2);
        GXLoadTexMtxImm((const f32 (*)[4])t2, 0x24, GX_MTX3x4);
        addSmallReflectionTevStage();
    }
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_DEFERRED_RENDER)
    {
        addRenderOpFadeStage(op);
    }
    {
        u8 e5 = obj->colorFadeFlags;
        if ((e5 & OBJ_COLOR_FADE_FLAG_ACTIVE) || (e5 & OBJ_COLOR_FADE_FLAG_OVERRIDE))
        {
            color[0] = obj->colorFadeRed;
            color[1] = obj->colorFadeGreen;
            color[2] = obj->colorFadeBlue;
            color[3] = obj->colorFadeAlpha;
            addColorFadeStage((GXColor*)color);
        }
    }
    if (op->flags & SHADER_FLAG_WATER_CAUSTIC)
    {
        AttractMovie_AddVideoTevStages();
    }
    Rcp_ApplyTextureStageCounts();
    {
        ObjModelRenderCb pcb = (ObjModelRenderCb)ObjModel_GetPostRenderCallback((ObjModel*)am);
        if (pcb != NULL)
        {
            pcb((int*)obj, am, idx);
        }
        else
        {
            u8 zon = 1;
            if (obj->anim.renderAlpha < 0xff || (op->flags & SHADER_FLAG_FORCE_BLEND) || shad)
            {
                u16 flags;
                GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
                flags = ((ModelFileHeader*)p2)->flags;
                if (flags & 0x400)
                {
                    gxSetZMode_(0, GX_LEQUAL, 0);
                    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                }
                else if (flags & 0x2000)
                {
                    zon = 0;
                    gxSetZMode_(1, GX_LEQUAL, 1);
                    GXSetAlphaCompare(GX_GREATER, gObjAlphaCompareThreshold, GX_AOP_AND, GX_GREATER, gObjAlphaCompareThreshold);
                }
                else
                {
                    gxSetZMode_(1, GX_LEQUAL, 0);
                    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
                }
            }
            else if (op->flags & SHADER_FLAG_ALPHA_TEST_OPAQUE)
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if (((ModelFileHeader*)p2)->flags & 0x400)
                {
                    gxSetZMode_(0, GX_LEQUAL, 0);
                }
                else
                {
                    gxSetZMode_(1, GX_LEQUAL, 1);
                }
                GXSetAlphaCompare(GX_GREATER, 0x40, GX_AOP_AND, GX_GREATER, 0x40);
            }
            else
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if (((ModelFileHeader*)p2)->flags & 0x400)
                {
                    gxSetZMode_(0, GX_LEQUAL, 0);
                }
                else
                {
                    gxSetZMode_(1, GX_LEQUAL, 1);
                }
                GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
            if (op->flags & SHADER_FLAG_ALPHA_TEST_OPAQUE)
            {
                zon = 0;
            }
            gxSetPeControl_ZCompLoc_(zon);
        }
    }
    if (op->flags & SHADER_FLAG_BACKFACE_CULL)
    {
        GXSetCullMode(GX_CULL_BACK);
    }
    else
    {
        GXSetCullMode(GX_CULL_NONE);
    }
    return idx;
}
static void shaderSetGxFlags(GameObject* obj, u8* m, u8* shader)
{
    u8 blend;
    u8 zwrite;
    u8 zcmp;
    u8 zcomploc;
    u32 alpha;
    u8 cull;
    u32 sf;
    if (obj->anim.renderAlpha < 0xff || ((sf = ((Shader*)shader)->flags) & SHADER_FLAG_FORCE_BLEND))
    {
        blend = 1;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
            zcomploc = 1;
            alpha = 0;
        }
        else if (((ModelFileHeader*)m)->flags & 0x2000)
        {
            zwrite = 1;
            zcmp = 1;
            zcomploc = 0;
            alpha = 0xdf;
        }
        else
        {
            zwrite = 1;
            zcmp = 0;
            zcomploc = 1;
            alpha = 0;
        }
    }
    else if (sf & SHADER_FLAG_ALPHA_TEST_OPAQUE)
    {
        blend = 0;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
        }
        else
        {
            zwrite = 1;
            zcmp = 1;
        }
        zcomploc = 0;
        alpha = 0x40;
    }
    else
    {
        blend = 0;
        if (((ModelFileHeader*)m)->flags & 0x400)
        {
            zwrite = 0;
            zcmp = 0;
        }
        else
        {
            zwrite = 1;
            zcmp = 1;
        }
        zcomploc = 1;
        alpha = 0;
    }
    if (((Shader*)shader)->flags & SHADER_FLAG_BACKFACE_CULL)
    {
        cull = 1;
    }
    else
    {
        cull = 0;
    }
    if (gObjGxBlendModeCache != blend)
    {
        if (blend != 0)
        {
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        }
        else
        {
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        }
        gObjGxBlendModeCache = blend;
    }
    if (gObjGxZWriteCache != zwrite || gObjGxZCompareCache != zcmp)
    {
        gxSetZMode_(zwrite, GX_LEQUAL, zcmp);
        gObjGxZWriteCache = zwrite;
        gObjGxZCompareCache = zcmp;
    }
    if (gObjGxZCompLocCache != zcomploc)
    {
        gxSetPeControl_ZCompLoc_(zcomploc);
        gObjGxZCompLocCache = zcomploc;
    }
    if (gObjGxAlphaCompareCache != alpha)
    {
        gObjGxAlphaCompareCache = alpha;
        if (alpha != 0)
        {
            GXSetAlphaCompare(GX_GREATER, (u8)alpha, GX_AOP_AND, GX_GREATER, (u8)alpha);
        }
        else
        {
            GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        }
    }
    if (cull != gObjGxCullModeCache)
    {
        gObjGxCullModeCache = cull;
        if (cull != 0)
        {
            GXSetCullMode(GX_CULL_BACK);
        }
        else
        {
            GXSetCullMode(GX_CULL_NONE);
        }
    }
}

extern f32 gObjJointMtxTemp[];
static void modelDoAltRenderInstrs(GameObject* obj, GameObject* obj2, u8* m, int p4)
{
    f32 wm[16];
    f32 cm[12];
    MtxBitStream bs;
    u8 color[4];
    ObjModelRenderCb cb;
    int* am = (int*)Obj_GetActiveModel(obj);
    if (curObjMtx != 0)
    {
        PSMTXCopy(curObjMtx, (MtxPtr)wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), (MtxPtr)wm, (MtxPtr)cm);
    if (!(((ObjModel*)am)->bufferFlags & 8))
    {
        ((ObjDef*)am)->hitboxStateIndex = 0;
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) &&
            ((ModelFileHeader*)m)->jointCount != 0)
        {
            if (gObjCachedModel != (u32)m)
            {
                ObjModel_UpdateAnimMatrices((ObjModel*)am, (ModelFileHeader*)m, obj, gObjJointMtxTemp);
                modelInitMtxs((ModelFileHeader*)m, (ObjModel*)am);
            }
            else
            {
                gModelMtxCacheState = 1;
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer((ObjModel*)am);
            PSMTXCopy((MtxPtr)gObjJointMtxTemp, (MtxPtr)(f32*)ObjModel_GetJointMatrix((u8*)am, 0));
            gModelMtxCacheState = 3;
        }
        {
            u8* att = (u8*)obj->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if ((s8)((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode < 0)
                {
                    ((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode = 0;
                }
            }
        }
        ((ObjModel*)am)->bufferFlags |= 8;
    }
    modelRenderInstrsState_init((ModelRenderInstrsState*)&bs, ((ModelFileHeader*)m)->instrs,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3);
    if (((ModelFileHeader*)m)->shaderFlags & MODEL_SHADERFLAGS_USE_OBJ_COLOR)
    {
        if (gObjOverrideColorPending != 0)
        {
            color[0] = gObjOverrideColor[0];
            color[1] = gObjOverrideColor[1];
            color[2] = gObjOverrideColor[2];
            gObjOverrideColorPending = 0;
        }
        else
        {
            objGetSunColor(obj->lightColorSlot, &color[0], &color[1], &color[2]);
        }
    }
    else
    {
        color[2] = 0xff;
        color[1] = 0xff;
        color[0] = 0xff;
    }
    color[3] = obj->anim.renderAlpha;
    cb = (ObjModelRenderCb)ObjModel_GetRenderCallback((ObjModel*)am);
    if (gObjRenderSetupDone == 0 || cb != NULL)
    {
        Camera_RebuildProjectionMatrix();
        if (cb == NULL || cb((int*)obj, am, 0) == 0)
        {
            _gxSetFogParams();
            Rcp_ResetTextureStageState();
            addTexLayerStageSwizzled(textureIdxToPtr(((ModelFileHeader*)m)->renderOps->layers[0].textureIndex), NULL,
                          0, (GXColor*)color, 0, 0);
            if (isHeavyFogEnabled() != 0)
            {
                u8 c[4];
                getFogColorRgb(c);
                renderHeavyFog(c);
            }
            Rcp_ApplyTextureStageCounts();
            GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
            gObjRenderSetupDone = 1;
            *(u32*)gObjGxKColorCache = *(u32*)color;
        }
    }
    else
    {
        void* tex = textureIdxToPtr(((ModelFileHeader*)m)->renderOps->layers[0].textureIndex);
        if (gObjCachedTexture != (u32)tex)
        {
            gObjCachedTexture = (u32)tex;
            selectTexture((Texture*)tex, 0);
        }
        if (gObjGxKColorCache[0] != color[0] || gObjGxKColorCache[1] != color[1] || gObjGxKColorCache[2] != color[2] ||
            gObjGxKColorCache[3] != color[3])
        {
            GXSetTevKColor(GX_KCOLOR0, *(GXColor*)color);
            *(u32*)gObjGxKColorCache = *(u32*)color;
        }
    }
    if (gObjCachedModel != (u32)m)
    {
        GXSetArray(GX_VA_POS,
                   (void*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1], 6);
        GXSetArray(GX_VA_TEX0, ((ModelFileHeader*)m)->texCoords, 4);
        gObjCachedModel = (u32)m;
    }
    shaderSetGxFlags(obj, m, (u8*)((ModelFileHeader*)m)->renderOps);
    bs.pos += 4;
    ModelHeader_setupPosTexFmt(m, (void*)((ModelFileHeader*)m)->renderOps, &bs, p4);
    bs.pos += 4;
    modelLoadMtxsToGx((ModelFileHeader*)m, am, &bs, cm);
    {
        ModelDisplayListEntry* dl;
        int idx;
        {
            u32 w;
            int pos = (bs.pos += 4);
            int off = pos >> 3;
            u8* p;
            w = bs.data[off];
            p = (u8*)(off + (char*)bs.data);
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 8;
            idx = (w >> (pos & 7)) & 0xff;
        }
        dl = modelFileGetDisplayList(m, idx);
        GXCallDisplayList(dl->dlist, dl->dlistSize);
    }
}


void objRenderInvalidateStateCache(void)
{
    gObjRenderSetupDone = 0;
    gObjCachedTexture = 0;
    gObjCachedModel = 0;
    lbl_803DCC34 = 0;
    gObjGxVtxDescCache = -1;
    gObjGxBlendModeCache = 0xff;
    gObjGxZCompLocCache = 0xff;
    gObjGxAlphaCompareCache = -1;
    gObjGxZWriteCache = 0xff;
    gObjGxZCompareCache = 0xff;
    gObjGxCullModeCache = 0xff;
    gObjGxKColorCache[3] = 0;
    gObjGxKColorCache[2] = 0;
    gObjGxKColorCache[1] = 0;
    gObjGxKColorCache[0] = 0;
}
typedef void (*ObjShadowCb)(GameObject* obj, int* am, f32* wm);

f32 gObjBoneMtxBuffer[0xC00];


static void objRenderShadowModel(GameObject* obj, GameObject* obj2, u8* m, int p4)
{
    int done;
    f32 cm[16];
    f32 wm[16];
    f32 im[16];
    MtxBitStream bs;
    u8 color[4];
    int* am;
    f32* vm;
    u8 did;
    Shader* op;
    u32 sh;

    am = (int*)Obj_GetActiveModel(obj);
    vm = Camera_GetViewMatrix();
    if (curObjMtx != 0)
    {
        PSMTXCopy(curObjMtx, (MtxPtr)wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    if (!(((ObjModel*)am)->bufferFlags & 8))
    {
        did = 0;
        ((ObjModel*)am)->vtxBufDirty = 0;
        ObjModel_ToggleVertexBuffer((ObjModel*)am);
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) &&
            ((ModelFileHeader*)m)->jointCount != 0)
        {
            if (((ModelFileHeader*)m)->vertexAnimEntries != NULL)
            {
                PSMTXIdentity((MtxPtr)im);
                ObjModel_UpdateAnimMatrices((ObjModel*)am, (ModelFileHeader*)m, obj, im);
                modelInitBoneMtxs2((ObjModel*)am, wm, gObjBoneMtxBuffer);
                did = 1;
            }
            else
            {
                ObjModel_UpdateAnimMatrices((ObjModel*)am, (ModelFileHeader*)m, obj, wm);
            }
            {
                ObjShadowCb cb = (ObjShadowCb)obj->afterBonesCallback;
                if (cb != NULL && obj2 == obj)
                {
                    cb(obj, am, wm);
                }
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer((ObjModel*)am);
            PSMTXCopy((MtxPtr)wm, (MtxPtr)(f32*)ObjModel_GetJointMatrix((u8*)am, 0));
        }
        if (((ModelFileHeader*)m)->morphTargetCount != 0)
        {
            ObjModel_ApplyBlendChannels((ObjModel*)am);
        }
        if (did != 0)
        {
            u8* vtx;
            if (((ObjModel*)am)->vtxBufDirty != 0)
            {
                vtx = (u8*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1];
            }
            else
            {
                vtx = (u8*)((ModelFileHeader*)m)->vertices;
            }
            ObjModel_BlendVertexStream(
                (u8*)gObjBoneMtxBuffer, m + 0x88, vtx,
                (int*)(int)((ModelFileHeader*)am)->jointBlendData,
                (u8*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1]);
            ObjModel_BlendNormalStream((u8*)gObjBoneMtxBuffer, m + 0xac,
                                       (u8*)(int)((ModelFileHeader*)m)->normals,
                                       (u8**)((ObjModel*)am)->blendAnimData,
                                       ((ModelFileHeader*)m)->flags24 & 8);
        }
        if (((ModelFileHeader*)m)->hitVolumeCount != 0)
        {
            objUpdateHitSpheres((u8*)am, m, (u8*)obj, NULL, (u8*)obj2);
        }
        else
        {
            u8* att = (u8*)obj->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if ((s8)((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode < 0)
                {
                    ((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode = 0;
                }
            }
        }
        ((ObjModel*)am)->bufferFlags |= 8;
    }
    modelInitMtxs((ModelFileHeader*)m, (ObjModel*)am);
    modelRenderInstrsState_init((ModelRenderInstrsState*)&bs, ((ModelFileHeader*)m)->instrs,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3);
    if (((ModelFileHeader*)m)->vertexAnimEntries != NULL)
    {
        PSMTXConcat((MtxPtr)vm, (MtxPtr)wm, (MtxPtr)cm);
        GXLoadPosMtxImm((const f32 (*)[4])cm, gObjGxPosMtxIdTable[9]);
    }
    {
        GameObject* o;
        GameObject* nxt;
        o = obj;
        while ((nxt = o->ownerObj) != NULL)
        {
            o = nxt;
        }
        sh = o->anim.modelState->shadowCastSlot->mode;
        if (sh == 0xff)
        {
            GXSetTevColor(GX_TEVREG2, lbl_803DB468);
            GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        }
        else
        {
            if (sh < 8)
            {
                color[0] = 1 << sh;
                color[1] = 0;
                color[2] = 0;
            }
            else
            {
                color[0] = 0;
                color[1] = 1 << (sh - 8);
                color[2] = 0;
            }
            color[3] = 0xff;
            GXSetTevColor(GX_TEVREG2, *(GXColor*)color);
            GXSetBlendMode(GX_BM_LOGIC, GX_BL_ONE, GX_BL_ZERO, GX_LO_OR);
        }
    }
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C2);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
    {
        gxSetZMode_(1, GX_LEQUAL, 1);
        GXSetCullMode(GX_CULL_FRONT);
    }
    else
    {
        gxSetZMode_(0, GX_LEQUAL, 0);
        GXSetCullMode(GX_CULL_NONE);
    }
    GXSetArray(GX_VA_POS,
               (void*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1], 6);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            u32 pAddr = (pos >> 3) + ((u32)bs.data + 1);
            w = *(u8*)(pAddr - 1);
            w |= *(u8*)pAddr << 8;
            w |= *(u8*)(pAddr + 1) << 16;
            bs.pos = pos + 4;
            op4 = (w >> (pos & 7)) & 0xf;
        }
        switch (op4)
        {
        case 3:
            GXClearVtxDesc();
            if (((ModelFileHeader*)m)->jointCount > 1)
            {
                GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
            }
            {
                u32 w;
                int pos = bs.pos;
                u32 pAddr = (pos >> 3) + ((u32)bs.data + 1);
                w = *(u8*)(pAddr - 1);
                w |= *(u8*)pAddr << 8;
                w |= *(u8*)(pAddr + 1) << 16;
                bs.pos = pos + 1;
                GXSetVtxDesc(GX_VA_POS, (((int)(w >> (pos & 7)) & 1) ? GX_INDEX16 : GX_INDEX8));
            }
            if (op->vtxAttrFlags & 1)
            {
                bs.pos += 1;
            }
            if (op->vtxAttrFlags & 2)
            {
                bs.pos += 1;
            }
            GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
            bs.pos += 1;
            break;
        case 1:
        {
            u32 w;
            int pos = bs.pos;
            u8* p = bs.data + (pos >> 3);
            w = p[0];
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 6;
            op = ObjModel_GetRenderOp((ModelFileHeader*)m, (w >> (pos & 7)) & 0x3f);
        }
        break;
        case 2:
        {
            ModelDisplayListEntry* dl;
            u32 w;
            int pos = bs.pos;
            u8* p = (u8*)((pos >> 3) + bs.data);
            w = p[0];
            w |= p[1] << 8;
            w |= p[2] << 16;
            bs.pos = pos + 8;
            dl = modelFileGetDisplayList(
                m, ((ModelFileHeader*)m)->displayListCount + ((w >> (pos & 7)) & 0xff));
            GXCallDisplayList(dl->dlist, dl->dlistSize);
        }
        break;
        case 4:
            modelLoadMtxsToGx((ModelFileHeader*)m, am, &bs, vm);
            break;
        case 5:
            done = 1;
            break;
        }
    }
}
extern u8 gObjGxTexMtxIdTable[12];

static void modelDoRenderInstrs(GameObject* obj, GameObject* obj2, u8* m, u8 passMask)
{
    int joff;
    f32 fm[16];
    f32 sm[16];
    f32 wm[16];
    f32 im[16];
    f32 tm[12];
    f32 t2m[12];
    MtxBitStream bs;
    u8 color[4];
    u8 o9;
    u8 o8;
    int* am;
    f32* vm;
    int passMaskCopy;
    int fuzzPass;
    int fuzzShadowPass;
    int shadowPass;
    u8 did;
    int* op;
    u32* refs;
    int done;
    f32 fade;
    f32 sc2;
    f32 sc;

    gObjRenderSetupDone = 0;
    gObjCachedTexture = 0;
    gObjCachedModel = 0;
    lbl_803DCC34 = 0;
    gObjGxVtxDescCache = -1;
    gObjGxBlendModeCache = 0xff;
    gObjGxZCompLocCache = 0xff;
    gObjGxAlphaCompareCache = -1;
    gObjGxZWriteCache = 0xff;
    gObjGxZCompareCache = 0xff;
    gObjGxCullModeCache = 0xff;
    gObjGxKColorCache[3] = 0;
    gObjGxKColorCache[2] = 0;
    gObjGxKColorCache[1] = 0;
    gObjGxKColorCache[0] = 0;
    am = (int*)Obj_GetActiveModel(obj);
    vm = Camera_GetViewMatrix();
    if (curObjMtx != 0)
    {
        PSMTXCopy(curObjMtx, (MtxPtr)wm);
        curObjMtx = 0;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(obj, wm, 0);
    }
    gObjShadowNear = 0;
    if (((ObjAnimComponent*)obj)->modelInstance->flags & OBJDEF_FLAG_ENABLE_CULLING)
    {
        GameObject* player = Obj_GetPlayerObject();
        GameObject* cam = (*gCameraInterface)->getCamera();
        if (player != NULL && !(player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) &&
            cam->anim.targetObj == player)
        {
            f32 d = 2e+01f + (obj->anim.hitboxScale * obj->anim.rootMotionScale +
                                    *(f32*)&obj->anim.targetObj);
            f32 dist = Camera_DistanceToCurrentViewPosition(player->anim.worldPosX, player->anim.worldPosY,
                                                            player->anim.worldPosZ);
            if (d > -dist)
            {
                gObjShadowNear = 1;
                gObjShadowDist = dist;
            }
        }
    }
    if (gObjOverrideColorPending != 0)
    {
        gObjCurChanColor.r = gObjOverrideColor[0];
        gObjCurChanColor.g = gObjOverrideColor[1];
        gObjCurChanColor.b = gObjOverrideColor[2];
        gObjOverrideColorPending = 0;
    }
    else
    {
        objGetSunColor(obj->lightColorSlot, &gObjCurChanColor.r, &gObjCurChanColor.g,
                    &gObjCurChanColor.b);
    }
    passMaskCopy = passMask;
    fuzzPass = passMaskCopy & 4;
    if (fuzzPass || (passMaskCopy & 8))
    {
        fade = 0.08f;
    }
    else if (passMaskCopy & 2)
    {
        fade = 0.15f;
    }
    did = 0;
    if (!(((ObjModel*)am)->bufferFlags & 8))
    {
        ((ObjModel*)am)->vtxBufDirty = 0;
        ObjModel_ToggleVertexBuffer((ObjModel*)am);
        if (((ModelFileHeader*)m)->animationCount != 0 && !(((ModelFileHeader*)m)->flags & 2) &&
            ((ModelFileHeader*)m)->jointCount != 0)
        {
            if (((ModelFileHeader*)m)->vertexAnimEntries != NULL)
            {
                PSMTXIdentity((MtxPtr)im);
                ObjModel_UpdateAnimMatrices((ObjModel*)am, (ModelFileHeader*)m, obj, im);
                if (fuzzPass == 0)
                {
                    modelInitBoneMtxs2((ObjModel*)am, wm, gObjBoneMtxBuffer);
                }
                else
                {
                    modelInitBoneMtxs((ObjModel*)am, gObjBoneMtxBuffer);
                }
                did = 1;
            }
            else
            {
                ObjModel_UpdateAnimMatrices((ObjModel*)am, (ModelFileHeader*)m, obj, wm);
            }
            {
                ObjShadowCb cb = (ObjShadowCb)obj->afterBonesCallback;
                if (cb != NULL && obj2 == obj)
                {
                    cb(obj, am, wm);
                }
            }
        }
        else
        {
            ObjModel_ToggleMatrixBuffer((ObjModel*)am);
            PSMTXCopy((MtxPtr)wm, (MtxPtr)(f32*)ObjModel_GetJointMatrix((u8*)am, 0));
        }
        if ((fuzzPass == 0 && (passMaskCopy & 8) == 0) || gObjFuzzLayerIndex == 0)
        {
            if (((ModelFileHeader*)m)->morphTargetCount != 0)
            {
                ObjModel_ApplyBlendChannels((ObjModel*)am);
            }
            if (did != 0)
            {
                u8* vtx;
                if (((ObjModel*)am)->vtxBufDirty != 0)
                {
                    vtx = (u8*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1];
                }
                else
                {
                    vtx = (u8*)((ModelFileHeader*)m)->vertices;
                }
                ObjModel_BlendVertexStream(
                    (u8*)gObjBoneMtxBuffer, m + 0x88, vtx,
                    (int*)(int)((ModelFileHeader*)am)->jointBlendData,
                    (u8*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1]);
                ObjModel_BlendNormalStream((u8*)gObjBoneMtxBuffer, m + 0xac,
                                           (u8*)(int)((ModelFileHeader*)m)->normals,
                                           (u8**)((ObjModel*)am)->blendAnimData,
                                           ((ModelFileHeader*)m)->flags24 & 8);
            }
        }
        if (((ModelFileHeader*)m)->hitVolumeCount != 0)
        {
            objUpdateHitSpheres((u8*)am, m, (u8*)obj, NULL, (u8*)obj2);
        }
        else
        {
            u8* att = (u8*)obj->anim.hitReactState;
            if (att != NULL)
            {
                att[0xaf]--;
                if ((s8)((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode < 0)
                {
                    ((ObjHitsPriorityState*)obj->anim.hitReactState)->resetHitboxMode = 0;
                }
            }
        }
        ((ObjModel*)am)->bufferFlags |= 8;
    }
    fuzzShadowPass = passMaskCopy & 2;
    if (fuzzShadowPass || fuzzPass || (passMaskCopy & 8))
    {
        int j;
        f32 one;
        j = 0;
        joff = 0;
        one = 1.0f;
        for (; j < ((ModelFileHeader*)m)->jointCount; j++)
        {
            f32* jm;

            sc = (f32)gObjFuzzStep * (fade / *(f32*)(((ModelFileHeader*)m)->jointBlendData + joff + 0xc)) + one;
            jm = (f32*)ObjModel_GetJointMatrix((u8*)am, j);
            PSMTXScale((MtxPtr)sm, sc, sc, sc);
            if (lbl_803DCC35 == 0)
            {
                {
                    char* jp = (char*)((ModelFileHeader*)m)->jointBlendData + joff;
                    PSMTXTrans((MtxPtr)tm, -*(f32*)jp, -*(f32*)(jp + 4), -*(f32*)(jp + 8));
                }
                PSMTXConcat((MtxPtr)sm, (MtxPtr)tm, (MtxPtr)sm);
                {
                    char* jp = (char*)((ModelFileHeader*)m)->jointBlendData + joff;
                    PSMTXTrans((MtxPtr)tm, *(f32*)jp, *(f32*)(jp + 4), *(f32*)(jp + 8));
                }
                PSMTXConcat((MtxPtr)tm, (MtxPtr)sm, (MtxPtr)sm);
            }
            PSMTXConcat((MtxPtr)jm, (MtxPtr)sm, (MtxPtr)jm);
            joff += 0x10;
        }
        if (did != 0)
        {
            model_multMtxs((u8*)am, wm);
        }
    }
    modelInitMtxs((ModelFileHeader*)m, (ObjModel*)am);
    modelRenderInstrsState_init((ModelRenderInstrsState*)&bs, ((ModelFileHeader*)m)->instrs,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3,
                                ((ModelFileHeader*)m)->instrsBitLenWords << 3);
    {
        f32 inv = 1.0f / obj->anim.rootMotionScale;
        PSMTXScale((MtxPtr)sm, inv, inv, inv);
    }
    if (((ModelFileHeader*)m)->vertexAnimEntries != NULL)
    {
        if (fuzzPass || fuzzShadowPass || (passMaskCopy & 8))
        {
            sc2 = 1.0f + (1.5f * ((f32)(gObjFuzzLayerIndex + 1) * fade)) / ((ModelFileHeader*)m)->vertexAnimScaleDivisor;
            PSMTXTrans((MtxPtr)tm, -((ModelFileHeader*)m)->vertexAnimPivot[0], -((ModelFileHeader*)m)->vertexAnimPivot[1], -((ModelFileHeader*)m)->vertexAnimPivot[2]);
            PSMTXScale((MtxPtr)sm, sc2, sc2, sc2);
            PSMTXConcat((MtxPtr)sm, (MtxPtr)tm, (MtxPtr)sm);
            PSMTXTrans((MtxPtr)tm, ((ModelFileHeader*)m)->vertexAnimPivot[0], ((ModelFileHeader*)m)->vertexAnimPivot[1], ((ModelFileHeader*)m)->vertexAnimPivot[2]);
            PSMTXConcat((MtxPtr)tm, (MtxPtr)sm, (MtxPtr)sm);
            PSMTXConcat((MtxPtr)wm, (MtxPtr)sm, (MtxPtr)t2m);
            PSMTXConcat((MtxPtr)vm, (MtxPtr)t2m, (MtxPtr)fm);
        }
        else
        {
            PSMTXConcat((MtxPtr)vm, (MtxPtr)wm, (MtxPtr)fm);
        }
        {
            f32 z;
            GXLoadPosMtxImm((const f32 (*)[4])fm, gObjGxPosMtxIdTable[9]);
            z = 0.0f;
            fm[3] = z;
            fm[7] = z;
            fm[11] = z;
            PSMTXConcat((MtxPtr)fm, (MtxPtr)sm, (MtxPtr)fm);
            GXLoadNrmMtxImm((const f32 (*)[4])fm, gObjGxPosMtxIdTable[9]);
            GXLoadTexMtxImm((const f32 (*)[4])fm, gObjGxTexMtxIdTable[9], GX_MTX3x4);
        }
    }
    shadowPass = passMaskCopy & 1;
    if (shadowPass != 0)
    {
        GXSetNumTexGens(0);
        GXSetNumTevStages(1);
        GXSetNumIndStages(0);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
        {
            u32 sh;
            GameObject* o;
            GameObject* nxt;
            o = obj;
            while ((nxt = o->ownerObj) != NULL)
            {
                o = nxt;
            }
            sh = o->anim.modelState->shadowCastSlot->mode;
            if (sh == 0xff)
            {
                GXSetTevColor(GX_TEVREG2, lbl_803DB468);
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
            }
            else
            {
                if (sh < 8)
                {
                    color[0] = 1 << sh;
                    color[1] = 0;
                    color[2] = 0;
                }
                else
                {
                    color[0] = 0;
                    color[1] = 1 << (sh - 8);
                    color[2] = 0;
                }
                color[3] = 0xff;
                GXSetTevColor(GX_TEVREG2, *(GXColor*)color);
                GXSetBlendMode(GX_BM_LOGIC, GX_BL_ONE, GX_BL_ZERO, GX_LO_OR);
            }
        }
        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C2);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
        GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(1);
        if (OBJPRINT_MODEL_DEF(obj)->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
        {
            gxSetZMode_(1, GX_LEQUAL, 1);
            GXSetCullMode(GX_CULL_FRONT);
        }
        else
        {
            gxSetZMode_(0, GX_LEQUAL, 0);
            GXSetCullMode(GX_CULL_NONE);
        }
    }
    else if (fuzzShadowPass != 0)
    {
        objFuzzSetupGxState(obj);
    }
    else
    {
        Camera_RebuildProjectionMatrix();
        objSetupLightChannels(m, obj);
        if (((ModelFileHeader*)m)->flags & 0x100)
        {
            GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, lbl_803DB468);
        }
        else
        {
            _gxSetFogParams();
        }
    }
    GXSetArray(GX_VA_POS,
               (void*)((int*)((char*)am + 0x1c))[(((ObjModel*)am)->bufferFlags >> 1) & 1], 6);
    if (((ModelFileHeader*)m)->flags24 & 8)
    {
        GXSetArray(GX_VA_NRM, ((ObjModel*)am)->normalBuf, 9);
    }
    else
    {
        GXSetArray(GX_VA_NRM, ((ObjModel*)am)->normalBuf, 3);
    }
    GXSetArray(GX_VA_CLR0, ((ModelFileHeader*)m)->colors, 2);
    GXSetArray(GX_VA_TEX0, ((ModelFileHeader*)m)->texCoords, 4);
    GXSetArray(GX_VA_TEX1, ((ModelFileHeader*)m)->texCoords, 4);
    done = 0;
    while (!done)
    {
        u32 op4;
        {
            u32 w;
            int pos = bs.pos;
            u32 pAddr = (pos >> 3) + ((u32)bs.data + 1);
            w = *(u8*)(pAddr - 1);
            w |= *(u8*)pAddr << 8;
            w |= *(u8*)(pAddr + 1) << 16;
            bs.pos = pos + 4;
            op4 = (w >> (pos & 7)) & 0xf;
        }
        switch (op4)
        {
        case 3:
            modelRenderFn_setVtxDescr(m, (u8*)op, refs, &bs, passMask, &o9, &o8);
            break;
        case 1:
        {
            u32 idx;
            if ((passMask == 0 || passMask == 4 || passMask == 8) && lbl_803DCC20 == 0)
            {
                idx = objSetupRenderOpGxState(obj, m, am, &bs);
                op = (int*)ObjModel_GetRenderOp((ModelFileHeader*)m, idx);
            }
            else
            {
                u32 w;
                int pos = bs.pos;
                u32 pAddr = (pos >> 3) + ((u32)bs.data + 1);
                w = *(u8*)(pAddr - 1);
                w |= *(u8*)pAddr << 8;
                w |= *(u8*)(pAddr + 1) << 16;
                bs.pos = pos + 6;
                idx = (w >> (pos & 7)) & 0x3f;
                op = (int*)ObjModel_GetRenderOp((ModelFileHeader*)m, idx);
            }
            refs = (u32*)ObjModel_GetRenderOpTextureRefs((ObjModel*)am, idx);
            break;
        }
        case 2:
            if ((passMask != 4 && passMask != 8) || gObjFuzzPassActive != 0)
            {
                ModelDisplayListEntry* dl;
                u32 w;
                int pos = bs.pos;
                u32 pAddr = (pos >> 3) + ((u32)bs.data + 1);
                w = *(u8*)(pAddr - 1);
                w |= *(u8*)pAddr << 8;
                w |= *(u8*)(pAddr + 1) << 16;
                bs.pos = pos + 8;
                dl = modelFileGetDisplayList(m, (w >> (pos & 7)) & 0xff);
                GXCallDisplayList(dl->dlist, dl->dlistSize);
            }
            else
            {
                bs.pos += 8;
            }
            break;
        case 4:
            renderOpMatrix(m, am, &bs, sm, vm, o9, o8, shadowPass);
            break;
        case 5:
            done = 1;
            break;
        }
    }
}


void objTransformHitVolumePoint(f32* mtx, f32* out, s16* in, int flag, GameObject* obj, int e);

void objUpdateHitVolumeTransforms(GameObject* obj)
{
    ObjDefHitVolume* p;
    ObjHitVolumeRuntimeTransform* q;
    int* model;
    ObjDefHitVolume* base;
    int i;
    base = obj->anim.modelInstance->hitVolumes;
    q = obj->anim.hitVolumeTransforms;
    if (!(*(u8*)&obj->anim.resetHitboxMode & 0x28))
    {
        model = (int*)Obj_GetActiveModel(obj);
        i = 0;
        p = base;
        for (; i < obj->anim.modelInstance->hitVolumeCount; i++)
        {
            int j = p->jointIndices[OBJPRINT_ACTIVE_BANK_INDEX(obj)];
            ObjModelJointMatrix* mtx;
            if (j >= 0)
            {
                mtx = ObjModel_GetJointMatrix((u8*)model, j);
            }
            else
            {
                mtx = NULL;
            }
            objTransformHitVolumePoint(NULL, &q->centerX, &p->posX, base->flags & 0x10, obj, 0);
            objTransformHitVolumePoint((f32*)mtx, &q->jointX, &p->jointOffsetX, base->flags & 0x10, obj, 1);
            p++;
            q++;
        }
    }
}


void objTransformHitVolumePoint(f32* mtx, f32* out, s16* in, int flag, GameObject* obj, int e)
{
    f32 m[16];
    MatrixTransform blk;
    f32 v[3];
    f32 res[3];
    v[0] = in[0];
    v[1] = in[1];
    v[2] = in[2];
    if (e != 0)
    {
        v[0] *= 0.00390625f;
        v[1] *= 0.00390625f;
        v[2] *= 0.00390625f;
    }
    if (mtx != NULL)
    {
        if (flag != 0)
        {
            out[0] = mtx[3] + v[0];
            out[1] = mtx[7] + v[1];
            out[2] = mtx[11] + v[2];
        }
        else
        {
            PSMTXMultVec((MtxPtr)mtx, (Vec*)v, (Vec*)res);
            out[0] = res[0];
            out[1] = res[1];
            out[2] = res[2];
        }
        out[0] += playerMapOffsetX;
        out[2] += playerMapOffsetZ;
    }
    else
    {
        blk.x = obj->anim.worldPosX;
        blk.y = obj->anim.worldPosY;
        blk.z = obj->anim.worldPosZ;
        if (flag != 0)
        {
            blk.rotX = 0;
            blk.rotY = 0;
            blk.rotZ = 0;
        }
        else
        {
            blk.rotX = obj->anim.rotX;
            blk.rotY = obj->anim.rotY;
            blk.rotZ = obj->anim.rotZ;
        }
        blk.scale = 1.0f;
        setMatrixFromObjectPos(m, &blk);
        Matrix_TransformPoint(m, v[0], v[1], v[2], &out[0], &out[1], &out[2]);
    }
}


void objSetOverrideColor(u8 r, u8 g, u8 b)
{
    gObjOverrideColorPending = 1;
    gObjOverrideColor[0] = r;
    gObjOverrideColor[1] = g;
    gObjOverrideColor[2] = b;
}

void objSetCurrentMatrix(MtxPtr x)
{
    curObjMtx = x;
}

void objRenderFuzzShells(GameObject* obj)
{
    int* model;
    MtxPtr savedMtx;
    gObjFuzzStep = 1;
    model = (int*)Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    gObjFuzzPhaseLatched = gObjFuzzPhase;
    ObjModel_SetRenderCallback((u8*)model, objFuzzShellRenderCb);
    for (gObjFuzzLayerIndex = 0; gObjFuzzLayerIndex < 16; gObjFuzzLayerIndex += gObjFuzzStep)
    {
        modelDoRenderInstrs(obj, obj->ownerObj ? obj->ownerObj : obj, (u8*)((ObjModel*)model)->file, 8);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    ObjModel_SetRenderCallback((u8*)model, NULL);
    gObjFuzzPhase += timeDelta;
    if (gObjFuzzPhase > 7.0f)
    {
        gObjFuzzPhase -= 8.0f;
    }
}

void objRenderFuzzShadowShells(GameObject* obj)
{
    int* model;
    MtxPtr savedMtx;
    gObjFuzzStep = 4;
    model = (int*)Obj_GetActiveModel(obj);
    savedMtx = curObjMtx;
    gObjFuzzPhaseLatched = gObjFuzzPhase;
    for (gObjFuzzLayerIndex = 0; gObjFuzzLayerIndex < 16; gObjFuzzLayerIndex += gObjFuzzStep)
    {
        modelDoRenderInstrs(obj, obj->ownerObj ? obj->ownerObj : obj, (u8*)((ObjModel*)model)->file, 2);
        curObjMtx = savedMtx;
    }
    curObjMtx = 0;
    gObjFuzzPhase += timeDelta;
    if (gObjFuzzPhase > 7.0f)
    {
        gObjFuzzPhase -= 8.0f;
    }
}

/* seqIds that always get the strong, high-segment-count fuzz (retail
   OBJECTS.bin names) */
#define OBJPRINT_SEQID_FRONT_FOX   0x77d /* "FrontFox" (DLL 0x2C0) */
#define OBJPRINT_SEQID_DIE_FOX     0x882 /* "DieFox" (DLL 0x10E) */
#define OBJPRINT_SEQID_DIE_KRYSTAL 0x887 /* "DieKrystal" (DLL 0x10E) */

void objRenderFuzz(GameObject* obj)
{
    int n;
    u8 maxN;
    int cnt;
    int* model;
    MtxPtr savedMtx;
    u8 strong;
    f32 dx, dy, dz, dist;
    Camera* cam = Camera_GetCurrent();
    if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) ||
        obj->anim.mapEventSlot == 0x3f ||
        obj->anim.romDefNo == OBJPRINT_SEQID_DIE_FOX ||
        obj->anim.romDefNo == OBJPRINT_SEQID_DIE_KRYSTAL)
    {
        strong = 1;
        if (obj->anim.classId == 1 ||
            obj->anim.romDefNo == OBJPRINT_SEQID_FRONT_FOX ||
            obj->anim.romDefNo == OBJPRINT_SEQID_DIE_FOX ||
            obj->anim.romDefNo == OBJPRINT_SEQID_DIE_KRYSTAL)
        {
            maxN = 0xf;
        }
        else
        {
            maxN = 7;
        }
    }
    else
    {
        strong = 0;
        maxN = 3;
    }
    {
        MtxPtr m = curObjMtx;
        if (m != 0)
        {
            dx = m[0][3] - (cam->x - playerMapOffsetX);
            dy = m[1][3] - cam->y;
            dz = m[2][3] - (cam->z - playerMapOffsetZ);
        }
        else
        {
            dx = obj->anim.worldPosX - cam->x;
            dy = obj->anim.worldPosY - cam->y;
            dz = obj->anim.worldPosZ - cam->z;
        }
    }
    dist = sqrtf(dx * dx + dy * dy + dz * dz);
    if (strong == 0)
    {
        cnt = (s32)((5.25f * (2.0f * dist)) /
                    (obj->anim.hitboxScale * obj->anim.rootMotionScale));
        gObjFuzzStep = 2;
    }
    else
    {
        cnt = (s32)((2.0f * dist) /
                    (obj->anim.hitboxScale * obj->anim.rootMotionScale));
        gObjFuzzStep = 1;
    }
    n = 16 - cnt;
    if (n > 0)
    {
        if (n > maxN)
        {
            n = maxN;
        }
        model = (int*)Obj_GetActiveModel(obj);
        savedMtx = curObjMtx;
        ObjModel_SetRenderCallback((u8*)model, objFuzzRenderCb);
        for (gObjFuzzLayerIndex = 0; gObjFuzzLayerIndex < n; gObjFuzzLayerIndex++)
        {
            modelDoRenderInstrs(obj, obj->ownerObj ? obj->ownerObj : obj, (u8*)((ObjModel*)model)->file, 4);
            curObjMtx = savedMtx;
        }
        curObjMtx = 0;
        ObjModel_SetRenderCallback((u8*)model, NULL);
    }
}

void objRenderShadow(GameObject* obj)
{
    if (obj->anim.rootMotionScale == 0.0f)
    {
        curObjMtx = 0;
        return;
    }
    {
        ModelFileHeader* m = (ModelFileHeader*)*(int**)Obj_GetActiveModel(obj);
        if (m->shadowDisplayListCount != 0)
        {
            objRenderShadowModel(obj, obj, (u8*)m, 1);
        }
        else
        {
            modelDoRenderInstrs(obj, obj, (u8*)m, 1);
        }
    }
    if (obj->anim.classId == 1)
    {
        u8* iter;
        int i = 0;
        iter = (u8*)obj;
        for (; i < obj->childCount; i++)
        {
            GameObject* child = ((GameObject*)iter)->childObjs[0];
            if (child != NULL)
            {
                objRenderChild(child, obj, 1);
            }
            iter += 4;
        }
    }
}

static void objRenderChild(GameObject* child, GameObject* parent, u8 isShadow)
{
    f32 res[3];
    MatrixTransform blk;
    f32 wm[16];
    f32 m2[16];
    f32 dx, dz;
    int off;
    f32* mtx;
    if (child->anim.rootMotionScale == 0.0f)
    {
        curObjMtx = 0;
        return;
    }
    Obj_GetActiveModel(child);
    {
        int* pmodel = (int*)Obj_GetActiveModel(parent);
        ObjAttachPoint* ent;
        int j;
        u8* tbl = (u8*)parent->anim.modelInstance->attachPoints;
        off = (child->objectFlags & 7) * 0x18;
        ent = (ObjAttachPoint*)(tbl + off);
        j = ent->joints[OBJPRINT_ACTIVE_BANK_INDEX(parent)];
        blk.x = *(f32*)(off + (char*)tbl);
        blk.y = ent->pos[1];
        blk.z = ent->pos[2];
        if (j == -1)
        {
            Obj_BuildWorldTransformMatrix(parent, wm, 0);
            mtx = wm;
        }
        else
        {
            mtx = (f32*)ObjModel_GetJointMatrix((u8*)pmodel, j);
        }
    }
    if (OBJPRINT_MODEL_DEF(child)->renderFlags & 8)
    {
        Camera* cam = Camera_GetCurrent();
        blk.scale = child->anim.rootMotionScale;
        dx = child->anim.localPosX - cam->x;
        dz = child->anim.localPosZ - cam->z;
        blk.rotX = getAngle(dx, dz) + 0x8000;
        blk.rotY = getAngle(child->anim.localPosY - cam->y,
                              sqrtf(dx * dx + dz * dz));
        blk.rotZ = cam->roll;
        setMatrixFromObjectTransposed(&blk, m2);
        res[0] = m2[3];
        res[1] = m2[7];
        res[2] = m2[11];
        PSMTXMultVec((MtxPtr)mtx, (Vec*)res, (Vec*)res);
        m2[3] = res[0];
        m2[7] = res[1];
        m2[11] = res[2];
    }
    else
    {
        ObjAttachPoint* pr;
        blk.scale = 1.0f;
        pr = (ObjAttachPoint*)((u8*)parent->anim.modelInstance->attachPoints + off);
        blk.rotX = pr->rot[0];
        blk.rotY = pr->rot[1];
        blk.rotZ = pr->rot[2];
        setMatrixFromObjectTransposed(&blk, m2);
        PSMTXConcat((MtxPtr)mtx, (MtxPtr)m2, (MtxPtr)m2);
    }
    if (isShadow == 0)
    {
        GameObject* space;
        child->anim.worldPosX = m2[3] + playerMapOffsetX;
        child->anim.worldPosY = m2[7];
        child->anim.worldPosZ = m2[11] + playerMapOffsetZ;
        space = child->anim.parent;
        if (space != NULL)
        {
            Obj_TransformWorldPointToLocal(child->anim.worldPosX, child->anim.worldPosY,
                                           child->anim.worldPosZ, &child->anim.localPosX,
                                           &child->anim.localPosY, &child->anim.localPosZ,
                                           space);
        }
        else
        {
            child->anim.localPosX = child->anim.worldPosX;
            child->anim.localPosY = child->anim.worldPosY;
            child->anim.localPosZ = child->anim.worldPosZ;
        }
        objMatrixToRotation(m2, &child->anim.rotX, &child->anim.rotY,
                             &child->anim.rotZ);
    }
    child->anim.renderAlpha =
        ((child->anim.alpha + 1) * parent->anim.renderAlpha) >> 8;
    child->sphereMapIntensity = parent->sphereMapIntensity;
    if (!(child->anim.flags & OBJANIM_FLAG_HIDDEN))
    {
        curObjMtx = (MtxPtr)m2;
        if (isShadow == 0)
        {
            child->objectFlags |= OBJECT_OBJFLAG_RENDERED;
            objRenderModel((GameObject*)child);
        }
        else
        {
            objRenderShadow(child);
        }
    }
}


/*
 * Bit-cursor over the model's render-instruction stream
 * (ModelFileHeader.instrs, bit length at header +0xD8 * 8).  Every reader
 * fetches 3 bytes little-endian around the cursor and shifts by (pos & 7).
 * Stream grammar (4-bit opcodes):
 *   1 = bind render op: 6-bit renderOps index (shader state setup)
 *   2 = draw: 8-bit display-list index -> GXCallDisplayList
 *   3 = vertex descriptor block: 1-bit pos/nrm/clr/tex size selectors
 *   4 = load matrices: 4-bit count, then 8-bit joint-matrix indices
 *   5 = end of stream
 * The stream is walked through a MtxBitStream (data at +0, cursor at +0x10).
 */

void objRenderModel(GameObject* obj)
{
    Texture* d1;
    f32 d2;
    int d3;
    int d4;
    f32 px;
    f32 py;
    f32 pz;
    s32 sx;
    s32 sy;
    s32 sz;
    u32 col;
    int* model = (int*)Obj_GetActiveModel(obj);
    if (obj->anim.rootMotionScale == 0.0f)
    {
        curObjMtx = 0;
        return;
    }
    {
        ModelFileHeader* m0 = ((ObjModel*)model)->file;
        if (m0->flags & 0x8000)
        {
            modelDoAltRenderInstrs(obj, obj->ownerObj ? obj->ownerObj : obj, (u8*)m0, 0);
        }
        else
        {
            modelDoRenderInstrs(obj, obj->ownerObj ? obj->ownerObj : obj, (u8*)m0, 0);
        }
    }
    {
        u8* iter;
        int i = 0;
        iter = (u8*)obj;
        for (; i < obj->childCount; i++)
        {
            GameObject* child = ((GameObject*)iter)->childObjs[0];
            if (child != NULL)
            {
                objRenderChild(child, obj, 0);
            }
            iter += 4;
        }
    }
    if (OBJPRINT_MODEL_DEF(obj)->shadowType != 4)
    {
        return;
    }
    if (gObjRenderingShadowPass != 0)
    {
        return;
    }
    {
        s16 romDefNo = obj->anim.romDefNo;
        if (romDefNo == 0x6a8)
            return;
        if (romDefNo == 0x6a9)
            return;
        if (romDefNo == 0x6aa)
            return;
        if (romDefNo == 0x6ab)
            return;
        if (romDefNo == 0x6ac)
            return;
        if (romDefNo == 0x752)
            return;
    }
    Camera_ProjectWorldPointWithOffset(
        obj->anim.localPosX - playerMapOffsetX, obj->anim.localPosY, obj->anim.localPosZ - playerMapOffsetZ,
        obj->anim.hitboxScale * obj->anim.rootMotionScale, &px, &py, &pz);
    Camera_ClipToScreen(px, py, pz, &sx, &sy, &sz);
    if (sz <= depthReadRequestPoll(sx, sy, obj))
    {
        obj->anim.modelState->shadowAlphaStep = 0x20;
    }
    else
    {
        obj->anim.modelState->shadowAlphaStep = -0x20;
    }
    {
        int alpha;
        alpha = obj->anim.modelState->shadowAlpha + obj->anim.modelState->shadowAlphaStep;
        if (alpha > 0xff)
        {
            obj->anim.modelState->shadowAlpha = 0xff;
        }
        else if (alpha < 0)
        {
            obj->anim.modelState->shadowAlpha = 0;
        }
        else
        {
            obj->anim.modelState->shadowAlpha += obj->anim.modelState->shadowAlphaStep;
        }
    }
    gObjShadowColor[3] = obj->anim.modelState->shadowAlpha;
    getObjectShadowDrawParams(obj, &d1, &d2, &d3, &d4);
    col = *(u32*)gObjShadowColor;
    hudDrawColored(d1, d3, d4, &col, (s32)(256.0f * d2), 1);
}

void objSetRenderingShadowPass(u8 x)
{
    gObjRenderingShadowPass = x;
}


u8 gObjGxPosMtxIdTable[12] = {0x00, 0x03, 0x06, 0x09, 0x0C, 0x0F, 0x12, 0x15, 0x18, 0x1B, 0x00, 0x00};
u8 gObjGxTexMtxIdTable[12] = {0x1E, 0x21, 0x24, 0x27, 0x2A, 0x2D, 0x30, 0x33, 0x36, 0x39, 0x00, 0x00};


f32 gObjJointMtxTemp[24] = {
    1.0f,         0.0f,           0.0f,           0.0f,           0.0f,           1.0f,
    0.0f,         0.0f,           0.0f,           0.0f,           1.0f,           0.0f,
    0.014794691f, 1.6930165e+22f, 2.5424896e+29f, 4.6243438e+30f, 1.6713787e-19f, 3.5253297e+09f,
    13.204376f,   1.8988991e+28f, 2.818281e+20f,  4.2326e+21f,    0.03909816f,    6.162976e-33f,
};
