#include "main/dll/cloudaction.h"
#include "main/rcp_dolphin_api.h"
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/objtexture.h"
#include "main/lightmap_api.h"
#include "main/sky_interface.h"
#include "main/shader_api.h"
#include "main/dll/savegame_env_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "string.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_api.h"
#include "main/hud_visibility_api.h"
#include "sys/objects.h"
#include "main/objprint_render_api.h"
#include "main/objprint_api.h"
#include "main/track_dolphin_api.h"
#include "main/model.h"
#include "main/sky_api.h"
#include "main/camera.h"
#include "dolphin/gx/GXEnum.h"
#include "main/sky.h"
#include "main/resource.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.gamecube.h"
#include "sys/objects/lifecycle.h"
#include "main/gx_scissor_api.h"
#include "main/pi_dolphin_api.h"
#include "main/newclouds.h"
#include "main/vecmath.h"

CloudActionRuntime gCloudActionRuntime;

GameObject* lbl_803DD1F0[2];
u8 gCloudOverridePositionValid;
f32 gCloudOverridePositionX;
f32 gCloudOverridePositionY;
f32 gCloudOverridePositionZ;

f32 gCloudActionGlareQuadSize[2] = {8000.0f, 0.0f};

#define GXWGFifo (*(volatile PPCWGPipe*)0xCC008000)

static inline void GXPos3f32(f32 x, f32 y, f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void GXTex2f32(f32 s, f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

void cloudClearOverridePosition(void)
{
    gCloudOverridePositionValid = 0;
}

void cloudSetOverridePosition(f32 a, f32 b, f32 c)
{
    gCloudOverridePositionValid = 1;
    gCloudOverridePositionX = a;
    gCloudOverridePositionY = b;
    gCloudOverridePositionZ = c;
}

void* cloudGetLayerTexture(f32* out1, f32* out2)
{
    ObjTextureRuntimeSlot* tex;
    int* layer;

    if (gCloudActionRuntime.mainCloudObj != NULL)
    {
        layer = Shader_getLayer(ObjModel_GetRenderOp(Obj_GetActiveModel(gCloudActionRuntime.mainCloudObj)->file, 0), 0);
        tex = objFindTexture((GameObject*)(gCloudActionRuntime.mainCloudObj), 0, 0);
        if (tex != NULL)
        {
            f32 scale = 0.0001f;
            *out1 = scale * tex->offsetS;
            *out2 = scale * tex->offsetT;
        }
        else
        {
            f32 d = 0.0f;
            *out1 = d;
            *out2 = d;
        }
        return textureIdxToPtr(*layer);
    }
    {
        f32 d = 0.0f;
        *out1 = d;
        *out2 = d;
    }
    return NULL;
}

void __kill_critical_regions(void)
{
}

void __begin_critical_region(void)
{
}

void __end_critical_region(void)
{
}

void cloudaction_func08_nop(void)
{
}

void cloudaction_func09_nop(void)
{
}

void cloudaction_free(void)
{
    if (gCloudActionRuntime.mainCloudObj != NULL)
    {
        Obj_FreeObject(gCloudActionRuntime.mainCloudObj);
        gCloudActionRuntime.mainCloudObj = NULL;
    }
    gCloudActionRuntime.mainCloudAssetId = 0;
    if (gCloudActionRuntime.upperCloudObj != NULL)
    {
        Obj_FreeObject(gCloudActionRuntime.upperCloudObj);
        gCloudActionRuntime.upperCloudObj = NULL;
    }
    gCloudActionRuntime.upperCloudAssetId = 0;
    if (gCloudActionRuntime.lowerCloudObj != NULL)
    {
        Obj_FreeObject(gCloudActionRuntime.lowerCloudObj);
        gCloudActionRuntime.lowerCloudObj = NULL;
    }
    gCloudActionRuntime.lowerCloudAssetId = 0;
}

void renderClouds(int a, int b, int c, int d)
{
    u8 ambientRed;
    u8 ambientGreen;
    u8 ambientBlue;
    u8 lightRed;
    u8 lightGreen;
    u8 lightBlue;
    int clipX;
    int clipY;
    int clipW;
    int clipH;
    u32 savedClipX;
    u32 savedClipY;
    u32 savedClipW;
    u32 savedClipH;
    Vec pos;
    Mtx mtx;
    Camera* view;
    ObjModel* model;
    MtxPtr viewMtx;
    f32 cloudT;
    f32 v;
    f32 c0;
    f32 c1;

    view = Camera_GetCurrent();
    (*gSkyInterface)
        ->getCurrentAmbientAndLightColors(&ambientRed, &ambientGreen, &ambientBlue, &lightRed, &lightGreen, &lightBlue);

    if (gCloudOverrideObject != NULL)
    {
        sky2ApplyModelTint(gCloudOverrideObject);
        model = Obj_GetActiveModel(gCloudOverrideObject);
        model->bufferFlags &= ~8;
        gCloudOverrideObject->anim.renderAlpha = 0xff;
        v = view->x;
        gCloudOverrideObject->anim.worldPosX = v;
        gCloudOverrideObject->anim.localPosX = v;
        v = view->y;
        gCloudOverrideObject->anim.worldPosY = v;
        gCloudOverrideObject->anim.localPosY = v;
        v = view->z;
        gCloudOverrideObject->anim.worldPosZ = v;
        gCloudOverrideObject->anim.localPosZ = v;
        objSetOverrideColor(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, gCloudOverrideObject, 1);
        return;
    }

    if (shouldDrawClouds() == 0)
    {
        return;
    }

    if (gCloudActionRuntime.upperCloudObj != NULL)
    {
        model = Obj_GetActiveModel((GameObject*)gCloudActionRuntime.upperCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)gCloudActionRuntime.upperCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            gCloudActionRuntime.upperCloudObj->anim.localPosX = gCloudOverridePositionX;
            gCloudActionRuntime.upperCloudObj->anim.localPosY = 300.0f + gCloudOverridePositionY;
            gCloudActionRuntime.upperCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            sky2ApplyModelTint((GameObject*)gCloudActionRuntime.upperCloudObj);
            gCloudActionRuntime.upperCloudObj->anim.localPosX = view->x;
            gCloudActionRuntime.upperCloudObj->anim.localPosY = view->y;
            gCloudActionRuntime.upperCloudObj->anim.localPosZ = view->z;
        }
        objSetOverrideColor(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, gCloudActionRuntime.upperCloudObj, 1);
    }

    if (gCloudActionRuntime.mainCloudObj != NULL)
    {
        if (isOvercast())
        {
            sky2ApplyModelTint((GameObject*)gCloudActionRuntime.mainCloudObj);
        }
        model = Obj_GetActiveModel((GameObject*)gCloudActionRuntime.mainCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)gCloudActionRuntime.mainCloudObj)[0x37] = 0xff;
        v = view->x;
        gCloudActionRuntime.mainCloudObj->anim.worldPosX = v;
        gCloudActionRuntime.mainCloudObj->anim.localPosX = v;
        v = 40.0f + view->y;
        gCloudActionRuntime.mainCloudObj->anim.worldPosY = v;
        gCloudActionRuntime.mainCloudObj->anim.localPosY = v;
        v = view->z;
        gCloudActionRuntime.mainCloudObj->anim.worldPosZ = v;
        gCloudActionRuntime.mainCloudObj->anim.localPosZ = v;
        gCloudActionRuntime.mainCloudObj->anim.rotY = 0;
        objSetOverrideColor(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, gCloudActionRuntime.mainCloudObj, 1);

        getSunFlareScissorRect(&clipX, &clipY, &clipW, &clipH);
        if (clipW > 0 && clipH > 0)
        {
            GXGetScissor(&savedClipX, &savedClipY, &savedClipW, &savedClipH);
            GXSetScissor(clipX, clipY, clipW, clipH);
            model->file->flags = model->file->flags | 0x2000;
            objSetAlphaCompareThreshold(0x80);
            GXSetColorUpdate(GX_FALSE);
            objRender(a, b, c, d, gCloudActionRuntime.mainCloudObj, 1);
            model->file->flags = model->file->flags & ~0x2000;
            objSetAlphaCompareThreshold(0);
            GXSetColorUpdate(GX_TRUE);
            GXSetScissor(savedClipX, savedClipY, savedClipW, savedClipH);
        }
    }

    cloudT = lightningGetRemainingFraction();
    if (cloudT > 0.0f)
    {
        lightningGetStartPos(&pos);
        pos.x -= playerMapOffsetX;
        pos.z -= playerMapOffsetZ;
        viewMtx = (MtxPtr)Camera_GetViewMatrix();
        GXSetCullMode(GX_CULL_NONE);
        Camera_RebuildProjectionMatrix();
        GXClearVtxDesc();
        GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        gxTevResetStages();
        gxTevColor1TexAlphaStage();
        gxTevCommitStages();
        gxSetAdditiveBlendNoZTest();
        PSMTXMultVec(viewMtx, &pos, &pos);
        PSMTXTrans(mtx, pos.x, pos.y, pos.z);
        GXLoadPosMtxImm(mtx, GX_PNMTX0);
        GXSetCurrentMtx(GX_PNMTX0);
        selectTexture((Texture*)skyGetSkyTexture(), 0);
        if (cloudT >= 0.5f)
        {
            _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
        }
        else
        {
            _gxSetTevColor2(0x80, 0x80, 0xff, (int)(2.0f * (255.0f * cloudT)));
        }
        if (getHudHiddenFrameCount() == 0)
        {
            gCloudActionGlareQuadSize[0] = randomGetRange(0x1f40, 0x2ee0);
        }
        GXBegin(GX_QUADS, GX_VTXFMT2, 4);
        c0 = 0.0f;
        c1 = 1.0f;
        v = -gCloudActionGlareQuadSize[0];
        GXPos3f32(v, v, c0);
        GXTex2f32(c0, c0);
        v = -gCloudActionGlareQuadSize[0];
        GXPos3f32(gCloudActionGlareQuadSize[0], v, c0);
        GXTex2f32(c1, c0);
        v = gCloudActionGlareQuadSize[0];
        GXPos3f32(gCloudActionGlareQuadSize[0], v, c0);
        GXTex2f32(c1, c1);
        v = gCloudActionGlareQuadSize[0];
        GXPos3f32(-v, v, c0);
        GXTex2f32(c0, c1);
    }

    if (gCloudActionRuntime.lowerCloudObj != NULL)
    {
        model = Obj_GetActiveModel((GameObject*)gCloudActionRuntime.lowerCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)gCloudActionRuntime.lowerCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            gCloudActionRuntime.lowerCloudObj->anim.localPosX = gCloudOverridePositionX;
            gCloudActionRuntime.lowerCloudObj->anim.localPosY = gCloudOverridePositionY - 50.0f;
            gCloudActionRuntime.lowerCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            sky2ApplyModelTint((GameObject*)gCloudActionRuntime.lowerCloudObj);
            gCloudActionRuntime.lowerCloudObj->anim.localPosX = view->x;
            gCloudActionRuntime.lowerCloudObj->anim.localPosY = view->y;
            gCloudActionRuntime.lowerCloudObj->anim.localPosZ = view->z;
        }
        objRender(a, b, c, d, gCloudActionRuntime.lowerCloudObj, 1);
    }
}

void cloudaction_scrollTexture(void)
{
    ObjTextureRuntimeSlot* tex;
    if (gCloudActionRuntime.mainCloudObj != NULL)
    {
        tex = objFindTexture((GameObject*)(gCloudActionRuntime.mainCloudObj), 0, 0);
        if (tex != NULL)
        {
            tex->offsetS -= gCloudActionRuntime.textureScrollStep;
            if (tex->offsetS < -0x2710)
            {
                tex->offsetS += 0x2710;
            }
        }
    }
}

void cloudaction_onMapSetup(void)
{
    memset(&gCloudActionRuntime, 0, sizeof(CloudActionRuntime));
}

typedef struct CloudActionConfig {
    u8 pad00[8];
    f32 scrollSpeed;    /* 0x08: /3 -> CloudActionRuntime.textureScrollStep */
    u8 pad0C[0x18];
    u16 envfxActId;     /* 0x24: 1-based; (id-1) saved into env-state +0xA, replayed on map setup */
    u8 pad26[0x32];
    u8 flags;           /* 0x58: bit1 gates the whole update (same gate as Sky2Config.flags) */
    u8 flags2;          /* 0x59: bit0 = apply clouds, bit2 = disable layer render */
    u8 lowerCloudIndex; /* 0x5A: index into gCloudActionEnvTbl.lowerCloudAssetIds, 0 = none */
    u8 upperCloudIndex; /* 0x5B: index into gCloudActionEnvTbl.upperCloudAssetIds, 0 = none */
    u8 pad5C;
    u8 mainCloudIndex;  /* 0x5D: index into gCloudActionEnvTbl.mainCloudAssetIds, 0 = none */
} CloudActionConfig;

STATIC_ASSERT(offsetof(CloudActionConfig, envfxActId) == 0x24);
STATIC_ASSERT(offsetof(CloudActionConfig, flags) == 0x58);
STATIC_ASSERT(offsetof(CloudActionConfig, mainCloudIndex) == 0x5D);

void cloudaction_update(int p1, int p2, u8* state, int p4, int val)
{
    CloudEnvTbl* tbl = &gCloudActionEnvTbl;
    CloudActionConfig* cfg = (CloudActionConfig*)state;
    SaveGameEnvState* envState;

    envState = saveGameGetEnvState();
    if (state == NULL)
    {
        return;
    }
    if ((cfg->flags & 2) == 0)
    {
        return;
    }
    envState->cloudActionEnvfxActId = (s16)((s16)cfg->envfxActId - 1);
    if ((cfg->flags2 & 1) == 0)
    {
        return;
    }
    lbl_803DB618[0] = lbl_803DB618[1];
    lbl_803DB618[1] = (u16)val;
    gCloudActionRuntime.textureScrollStep = cfg->scrollSpeed / 3.0f;
    gCloudActionRuntime.pad19 = 0;
    if ((cfg->flags2 & 4) != 0)
    {
        gCloudActionRuntime.layerRenderEnabled = 0;
    }
    else
    {
        gCloudActionRuntime.layerRenderEnabled = 1;
    }
    if (cfg->mainCloudIndex != 0)
    {
        if (cfg->mainCloudIndex < 5)
        {
            if (gCloudActionRuntime.mainCloudAssetId != tbl->mainCloudAssetIds[cfg->mainCloudIndex])
            {
                if (gCloudActionRuntime.mainCloudObj != NULL)
                {
                    Obj_FreeObject(gCloudActionRuntime.mainCloudObj);
                }
                gCloudActionRuntime.mainCloudObj =
                    (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x20, tbl->mainCloudAssetIds[cfg->mainCloudIndex]),
                                                 4, -1, -1, 0);
                gCloudActionRuntime.mainCloudAssetId = tbl->mainCloudAssetIds[cfg->mainCloudIndex];
            }
        }
    }
    else
    {
        if (gCloudActionRuntime.mainCloudObj != NULL)
        {
            Obj_FreeObject(gCloudActionRuntime.mainCloudObj);
            gCloudActionRuntime.mainCloudObj = NULL;
        }
        gCloudActionRuntime.mainCloudAssetId = 0;
    }
    if (cfg->upperCloudIndex != 0)
    {
        if (cfg->upperCloudIndex < 4)
        {
            if (gCloudActionRuntime.upperCloudAssetId != tbl->upperCloudAssetIds[cfg->upperCloudIndex])
            {
                if (gCloudActionRuntime.upperCloudObj != NULL)
                {
                    Obj_FreeObject(gCloudActionRuntime.upperCloudObj);
                }
                gCloudActionRuntime.upperCloudObj =
                    (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x20, tbl->upperCloudAssetIds[cfg->upperCloudIndex]),
                                                 4, -1, -1, 0);
                gCloudActionRuntime.upperCloudAssetId = tbl->upperCloudAssetIds[cfg->upperCloudIndex];
            }
        }
    }
    else
    {
        if (gCloudActionRuntime.upperCloudObj != NULL)
        {
            Obj_FreeObject(gCloudActionRuntime.upperCloudObj);
            gCloudActionRuntime.upperCloudObj = NULL;
        }
        gCloudActionRuntime.upperCloudAssetId = 0;
    }
    if (cfg->lowerCloudIndex != 0)
    {
        if (cfg->lowerCloudIndex < 5)
        {
            if (gCloudActionRuntime.lowerCloudAssetId != tbl->lowerCloudAssetIds[cfg->lowerCloudIndex])
            {
                if (gCloudActionRuntime.lowerCloudObj != NULL)
                {
                    Obj_FreeObject(gCloudActionRuntime.lowerCloudObj);
                }
                gCloudActionRuntime.lowerCloudObj =
                    (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x20, tbl->lowerCloudAssetIds[cfg->lowerCloudIndex]),
                                                 4, -1, -1, 0);
                gCloudActionRuntime.lowerCloudAssetId = tbl->lowerCloudAssetIds[cfg->lowerCloudIndex];
            }
        }
    }
    else
    {
        if (gCloudActionRuntime.lowerCloudObj != NULL)
        {
            Obj_FreeObject(gCloudActionRuntime.lowerCloudObj);
            gCloudActionRuntime.lowerCloudObj = NULL;
        }
        gCloudActionRuntime.lowerCloudAssetId = 0;
    }
}

void cloudaction_release(void)
{
}

void cloudaction_initialise(void)
{
    lbl_803DB618[0] = -1;
    lbl_803DB618[1] = -1;
    gCloudOverrideObject = NULL;
}

CloudEnvTbl gCloudActionEnvTbl = {
    {0, 1575, 1577, 1886, 1525},
    {0, 1576, 1890, 2147},
    {0, 1578, 2140, 2145, 2147},
};

ResourceDescriptorCallbacks14 cloudaction_funcs = {
    {0x00000000, 0x00000000, 0x00000000, 0x000c0000},
    {(ResourceDescriptorCallback)cloudaction_initialise,
     (ResourceDescriptorCallback)cloudaction_release,
     0x00000000,
     (ResourceDescriptorCallback)cloudaction_update,
     (ResourceDescriptorCallback)cloudaction_onMapSetup,
     (ResourceDescriptorCallback)cloudaction_scrollTexture,
     (ResourceDescriptorCallback)renderClouds,
     (ResourceDescriptorCallback)cloudaction_free,
     (ResourceDescriptorCallback)cloudaction_func08_nop,
     (ResourceDescriptorCallback)cloudaction_func09_nop,
     (ResourceDescriptorCallback)__end_critical_region,
     (ResourceDescriptorCallback)__begin_critical_region,
     (ResourceDescriptorCallback)__kill_critical_regions,
     0x00000000}};
