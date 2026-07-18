/*
 * cloudaction - the sky-cloud layer renderer/updater for the env-fx DLL
 * (shares its TU/runtime with the water and explosion fx). It owns up to
 * three cloud-layer objects in
 * CloudActionRuntime (lbl_8039AB28): a main layer, an upper layer and a
 * lower layer, each spawned from an asset id picked out of the per-env
 * CloudEnvTbl (gCloudActionEnvTbl) by the current environment's layer-state
 * bytes.
 *
 * renderClouds() positions each live layer to the current camera view
 * slot (or to the gCloudOverride* position when one is set), draws it via
 * objRender, and additionally draws a procedural sun/glare quad through
 * the GX FIFO when the active lightning flash's remaining-life fraction
 * (lightningGetRemainingFraction) is above threshold. cloudaction_update() re-reads the env layer state each step,
 * (re)spawns/frees the three layers as their asset ids change, and feeds
 * the texture-scroll step; cloudaction_func05() scrolls the main layer's
 * texture each frame.
 */
#include "main/dll/cloudaction.h"
#include "main/newclouds.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/texture.h"
#include "main/dll/waterfx.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/objtexture.h"
#include "main/lightmap_api.h"
#include "main/sky_interface.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/dll/savegame_env_api.h"
#include "main/gx_scissor_api.h"
#include "dolphin/gx/GXLegacyDecls.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_api.h"
#include "main/hud_visibility_api.h"
#include "main/object_api.h"
#include "main/objprint_render_api.h"
#include "main/objprint_api.h"
#include "main/track_dolphin_api.h"
#include "main/model.h"
#include "main/sky_api.h"
#include "main/camera.h"
#include "dolphin/gx/GXEnum.h"
#include "string.h"
#include "main/sky.h"
#include "main/resource.h"

CloudActionRuntime lbl_8039AB28;

GameObject* lbl_803DD1F0[2];
u8 cloudOverridePosition;
f32 lbl_803DD1E8;
f32 lbl_803DD1E4;
f32 lbl_803DD1E0;

f32 gCloudActionGlareQuadSize = 8000.0f;

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

void* cloudGetLayerTextureSize(f32* out1, f32* out2)
{
    ObjTextureRuntimeSlot* tex;
    int* layer;

    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        layer = (int*)Shader_getLayer(ObjModel_GetRenderOp(Obj_GetActiveModel(lbl_8039AB28.mainCloudObj)->file, 0), 0);
        tex = objFindTexture((GameObject*)(lbl_8039AB28.mainCloudObj), 0, 0);
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
    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        Obj_FreeObject(lbl_8039AB28.mainCloudObj);
        lbl_8039AB28.mainCloudObj = NULL;
    }
    lbl_8039AB28.mainCloudAssetId = 0;
    if (lbl_8039AB28.upperCloudObj != NULL)
    {
        Obj_FreeObject(lbl_8039AB28.upperCloudObj);
        lbl_8039AB28.upperCloudObj = NULL;
    }
    lbl_8039AB28.upperCloudAssetId = 0;
    if (lbl_8039AB28.lowerCloudObj != NULL)
    {
        Obj_FreeObject(lbl_8039AB28.lowerCloudObj);
        lbl_8039AB28.lowerCloudObj = NULL;
    }
    lbl_8039AB28.lowerCloudAssetId = 0;
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
    f32 pos[3];
    f32 mtx[12];
    CameraViewSlot* view;
    ObjModel* model;
    void* viewMtx;
    f32 cloudT;
    f32 v;
    f32 c0;
    f32 c1;

    view = Camera_GetCurrentViewSlot();
    (*gSkyInterface)
        ->getCurrentAmbientAndLightColors(&ambientRed, &ambientGreen, &ambientBlue, &lightRed, &lightGreen, &lightBlue);

    if (gCloudOverrideObject != NULL)
    {
        fn_8008DAE8((int)gCloudOverrideObject);
        model = Obj_GetActiveModel((GameObject*)gCloudOverrideObject);
        model->bufferFlags &= ~8;
        ((u8*)gCloudOverrideObject)[0x37] = 0xff;
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

    if (lbl_8039AB28.upperCloudObj != NULL)
    {
        model = Obj_GetActiveModel((GameObject*)lbl_8039AB28.upperCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)lbl_8039AB28.upperCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            lbl_8039AB28.upperCloudObj->anim.localPosX = gCloudOverridePositionX;
            lbl_8039AB28.upperCloudObj->anim.localPosY = 300.0f + gCloudOverridePositionY;
            lbl_8039AB28.upperCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            fn_8008DAE8((int)lbl_8039AB28.upperCloudObj);
            lbl_8039AB28.upperCloudObj->anim.localPosX = view->x;
            lbl_8039AB28.upperCloudObj->anim.localPosY = view->y;
            lbl_8039AB28.upperCloudObj->anim.localPosZ = view->z;
        }
        objSetOverrideColor(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, lbl_8039AB28.upperCloudObj, 1);
    }

    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        if (isOvercast())
        {
            fn_8008DAE8((int)lbl_8039AB28.mainCloudObj);
        }
        model = Obj_GetActiveModel((GameObject*)lbl_8039AB28.mainCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)lbl_8039AB28.mainCloudObj)[0x37] = 0xff;
        v = view->x;
        lbl_8039AB28.mainCloudObj->anim.worldPosX = v;
        lbl_8039AB28.mainCloudObj->anim.localPosX = v;
        v = 40.0f + view->y;
        lbl_8039AB28.mainCloudObj->anim.worldPosY = v;
        lbl_8039AB28.mainCloudObj->anim.localPosY = v;
        v = view->z;
        lbl_8039AB28.mainCloudObj->anim.worldPosZ = v;
        lbl_8039AB28.mainCloudObj->anim.localPosZ = v;
        lbl_8039AB28.mainCloudObj->anim.rotY = 0;
        objSetOverrideColor(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, lbl_8039AB28.mainCloudObj, 1);

        fn_80060490(&clipX, &clipY, &clipW, &clipH);
        if (clipW > 0 && clipH > 0)
        {
            GXGetScissor(&savedClipX, &savedClipY, &savedClipW, &savedClipH);
            GXSetScissor(clipX, clipY, clipW, clipH);
            model->file->flags = model->file->flags | 0x2000;
            objSetAlphaCompareThreshold(0x80);
            GXSetColorUpdate(GX_FALSE);
            objRender(a, b, c, d, lbl_8039AB28.mainCloudObj, 1);
            model->file->flags = model->file->flags & ~0x2000;
            objSetAlphaCompareThreshold(0);
            GXSetColorUpdate(GX_TRUE);
            GXSetScissor(savedClipX, savedClipY, savedClipW, savedClipH);
        }
    }

    cloudT = lightningGetRemainingFraction();
    if (cloudT > 0.0f)
    {
        lightningGetStartPos(pos);
        pos[0] -= playerMapOffsetX;
        pos[2] -= playerMapOffsetZ;
        viewMtx = Camera_GetViewMatrix();
        GXSetCullMode(GX_CULL_NONE);
        Camera_RebuildProjectionMatrix();
        GXClearVtxDesc();
        GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        textureSetupFn_800799c0();
        gxTextureFn_800794e0();
        textRenderSetupFn_80079804();
        gxBlendFn_800789ac();
        PSMTXMultVec(viewMtx, pos, pos);
        PSMTXTrans(mtx, pos[0], pos[1], pos[2]);
        GXLoadPosMtxImm(mtx, GX_PNMTX0);
        GXSetCurrentMtx(GX_PNMTX0);
        selectTexture((Texture*)fn_8008912C(), 0);
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
            gCloudActionGlareQuadSize = randomGetRange(0x1f40, 0x2ee0);
        }
        GXBegin(GX_QUADS, GX_VTXFMT2, 4);
        c0 = 0.0f;
        c1 = 1.0f;
        GXPos3f32(-gCloudActionGlareQuadSize, -gCloudActionGlareQuadSize, c0);
        GXTex2f32(c0, c0);
        GXPos3f32(gCloudActionGlareQuadSize, -gCloudActionGlareQuadSize, c0);
        GXTex2f32(c1, c0);
        GXPos3f32(gCloudActionGlareQuadSize, gCloudActionGlareQuadSize, c0);
        GXTex2f32(c1, c1);
        GXPos3f32(-gCloudActionGlareQuadSize, gCloudActionGlareQuadSize, c0);
        GXTex2f32(c0, c1);
    }

    if (lbl_8039AB28.lowerCloudObj != NULL)
    {
        model = Obj_GetActiveModel((GameObject*)lbl_8039AB28.lowerCloudObj);
        model->bufferFlags &= ~8;
        ((u8*)lbl_8039AB28.lowerCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            lbl_8039AB28.lowerCloudObj->anim.localPosX = gCloudOverridePositionX;
            lbl_8039AB28.lowerCloudObj->anim.localPosY = gCloudOverridePositionY - 50.0f;
            lbl_8039AB28.lowerCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            fn_8008DAE8((int)lbl_8039AB28.lowerCloudObj);
            lbl_8039AB28.lowerCloudObj->anim.localPosX = view->x;
            lbl_8039AB28.lowerCloudObj->anim.localPosY = view->y;
            lbl_8039AB28.lowerCloudObj->anim.localPosZ = view->z;
        }
        objRender(a, b, c, d, lbl_8039AB28.lowerCloudObj, 1);
    }
}

void cloudaction_func05(void)
{
    ObjTextureRuntimeSlot* tex;
    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        tex = objFindTexture((GameObject*)(lbl_8039AB28.mainCloudObj), 0, 0);
        if (tex != NULL)
        {
            tex->offsetS -= lbl_8039AB28.textureScrollStep;
            if (tex->offsetS < -0x2710)
            {
                tex->offsetS += 0x2710;
            }
        }
    }
}

void cloudaction_onMapSetup(void)
{
    memset(&lbl_8039AB28, 0, sizeof(CloudActionRuntime));
}

void cloudaction_update(int p1, int p2, u8* state, int p4, int val)
{
    CloudEnvTbl* tbl = &gCloudActionEnvTbl;
    void* envState;

    envState = saveGameGetEnvState();
    if (state == NULL)
    {
        return;
    }
    if ((state[0x58] & 2) == 0)
    {
        return;
    }
    *(s16*)((u8*)envState + 0xa) = (s16)((s16) * (u16*)(state + 0x24) - 1);
    if ((state[0x59] & 1) == 0)
    {
        return;
    }
    lbl_803DB618[0] = lbl_803DB618[1];
    lbl_803DB618[1] = (u16)val;
    lbl_8039AB28.textureScrollStep = *(f32*)(state + 8) / 3.0f;
    lbl_8039AB28.pad19 = 0;
    if ((*(u8*)(state + 0x59) & 4) != 0)
    {
        lbl_8039AB28.layerRenderEnabled = 0;
    }
    else
    {
        lbl_8039AB28.layerRenderEnabled = 1;
    }
    if (state[0x5d] != 0)
    {
        if (state[0x5d] < 5)
        {
            if (lbl_8039AB28.mainCloudAssetId != tbl->mainCloudAssetIds[state[0x5d]])
            {
                if (lbl_8039AB28.mainCloudObj != NULL)
                {
                    Obj_FreeObject(lbl_8039AB28.mainCloudObj);
                }
                lbl_8039AB28.mainCloudObj =
                    (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x20, tbl->mainCloudAssetIds[state[0x5d]]),
                                                 4, -1, -1, 0);
                lbl_8039AB28.mainCloudAssetId = tbl->mainCloudAssetIds[state[0x5d]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.mainCloudObj != NULL)
        {
            Obj_FreeObject(lbl_8039AB28.mainCloudObj);
            lbl_8039AB28.mainCloudObj = NULL;
        }
        lbl_8039AB28.mainCloudAssetId = 0;
    }
    if (state[0x5b] != 0)
    {
        if (state[0x5b] < 4)
        {
            if (lbl_8039AB28.upperCloudAssetId != tbl->upperCloudAssetIds[state[0x5b]])
            {
                if (lbl_8039AB28.upperCloudObj != NULL)
                {
                    Obj_FreeObject(lbl_8039AB28.upperCloudObj);
                }
                lbl_8039AB28.upperCloudObj =
                    (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x20, tbl->upperCloudAssetIds[state[0x5b]]),
                                                 4, -1, -1, 0);
                lbl_8039AB28.upperCloudAssetId = tbl->upperCloudAssetIds[state[0x5b]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.upperCloudObj != NULL)
        {
            Obj_FreeObject(lbl_8039AB28.upperCloudObj);
            lbl_8039AB28.upperCloudObj = NULL;
        }
        lbl_8039AB28.upperCloudAssetId = 0;
    }
    if (state[0x5a] != 0)
    {
        if (state[0x5a] < 5)
        {
            if (lbl_8039AB28.lowerCloudAssetId != tbl->lowerCloudAssetIds[state[0x5a]])
            {
                if (lbl_8039AB28.lowerCloudObj != NULL)
                {
                    Obj_FreeObject(lbl_8039AB28.lowerCloudObj);
                }
                lbl_8039AB28.lowerCloudObj =
                    (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x20, tbl->lowerCloudAssetIds[state[0x5a]]),
                                                 4, -1, -1, 0);
                lbl_8039AB28.lowerCloudAssetId = tbl->lowerCloudAssetIds[state[0x5a]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.lowerCloudObj != NULL)
        {
            Obj_FreeObject(lbl_8039AB28.lowerCloudObj);
            lbl_8039AB28.lowerCloudObj = NULL;
        }
        lbl_8039AB28.lowerCloudAssetId = 0;
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

/* descriptor/ptr table auto 0x8030f7e8-0x8030f86c */
ResourceDescriptorCallbacks14 lbl_8030F7E8 = {
    {0x00000000, 0x00000000, 0x00000000, 0x000c0000},
    {(ResourceDescriptorCallback)cloudaction_initialise,
     (ResourceDescriptorCallback)cloudaction_release,
     0x00000000,
     (ResourceDescriptorCallback)cloudaction_update,
     (ResourceDescriptorCallback)cloudaction_onMapSetup,
     (ResourceDescriptorCallback)cloudaction_func05,
     (ResourceDescriptorCallback)renderClouds,
     (ResourceDescriptorCallback)cloudaction_free,
     (ResourceDescriptorCallback)cloudaction_func08_nop,
     (ResourceDescriptorCallback)cloudaction_func09_nop,
     (ResourceDescriptorCallback)__end_critical_region,
     (ResourceDescriptorCallback)__begin_critical_region,
     (ResourceDescriptorCallback)__kill_critical_regions,
     0x00000000}};
ResourceDescriptorCallbacks11 lbl_8030F830 = {
    {0x00000000, 0x00000000, 0x00000000, 0x000a0000},
    {(ResourceDescriptorCallback)waterfx_initialise,
     (ResourceDescriptorCallback)waterfx_release,
     0x00000000,
     (ResourceDescriptorCallback)waterfx_run,
     (ResourceDescriptorCallback)waterfx_func04,
     (ResourceDescriptorCallback)waterfx_func05,
     (ResourceDescriptorCallback)waterfx_spawnSplashBurst,
     (ResourceDescriptorCallback)waterfx_spawnRipple,
     (ResourceDescriptorCallback)waterfx_func08,
     (ResourceDescriptorCallback)waterfx_onMapSetup,
     (ResourceDescriptorCallback)waterfx_setRippleScale}};
