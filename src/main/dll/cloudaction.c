/*
 * cloudaction - the sky-cloud layer renderer/updater for the env-fx DLL
 * (shares its TU/runtime with the water and explosion fx via
 * fx_800944A0_shared.h). It owns up to three cloud-layer objects in
 * CloudActionRuntime (lbl_8039AB28): a main layer, an upper layer and a
 * lower layer, each spawned from an asset id picked out of the per-env
 * CloudEnvTbl (gCloudActionEnvTbl) by the current environment's layer-state
 * bytes.
 *
 * renderClouds() positions each live layer to the current camera view
 * slot (or to the gCloudOverride* position when one is set), draws it via
 * objRender, and additionally draws a procedural sun/glare quad through
 * the GX FIFO when the sky's cloud factor (fn_8008ED88) is above
 * threshold. cloudaction_update() re-reads the env layer state each step,
 * (re)spawns/frees the three layers as their asset ids change, and feeds
 * the texture-scroll step; cloudaction_func05() scrolls the main layer's
 * texture each frame.
 */
#include "main/dll/fx_800944A0_shared.h"

volatile PPCWGPipe GXWGFifo : (0xCC008000);

extern void* Camera_GetCurrentViewSlot(void);
extern void fn_8008DAE8(int obj);
extern u8* Obj_GetActiveModel(int obj);
extern void fn_800412B8(int a, int b, int c);
extern void objRender(int a, int b, int c, int d, int obj, int flag);
extern int shouldDrawClouds(void);
extern u8 isOvercast(void);
extern void fn_80060490(int* a, int* b, int* c, int* d);
extern void GXGetScissor(int* x, int* y, int* w, int* h);
extern void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht);
extern void fn_8003BB7C(int a);
extern void GXSetColorUpdate(int enable);
extern f32 fn_8008ED88(void);
extern void fn_8008EDE8(f32 * pos);
extern void Camera_RebuildProjectionMatrix(void);
extern void textureSetupFn_800799c0(void);
extern void gxTextureFn_800794e0(void);
extern void textRenderSetupFn_80079804(void);
extern void gxBlendFn_800789ac(void);
extern void PSMTXMultVec(void* m, f32* src, f32* dst);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern int fn_8008912C(void);
extern void selectTexture(int tex, int a);
extern void _gxSetTevColor2(int r, int g, int b, int a);
extern int getHudHiddenFrameCount(void);
extern volatile f32 gCloudActionGlareQuadSize;
extern const f32 lbl_803DF2B4;
extern const f32 lbl_803DF2C0;
extern const f32 lbl_803DF2C4;
extern const f32 lbl_803DF2C8;
extern const f32 lbl_803DF2CC;
extern const f32 lbl_803DF2D0;
extern const f32 lbl_803DF2D4;
extern const f32 lbl_803DF2D8;

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
        Obj_FreeObject((int)lbl_8039AB28.mainCloudObj);
        lbl_8039AB28.mainCloudObj = NULL;
    }
    lbl_8039AB28.mainCloudAssetId = 0;
    if (lbl_8039AB28.upperCloudObj != NULL)
    {
        Obj_FreeObject((int)lbl_8039AB28.upperCloudObj);
        lbl_8039AB28.upperCloudObj = NULL;
    }
    lbl_8039AB28.upperCloudAssetId = 0;
    if (lbl_8039AB28.lowerCloudObj != NULL)
    {
        Obj_FreeObject((int)lbl_8039AB28.lowerCloudObj);
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
    int savedClipX;
    int savedClipY;
    int savedClipW;
    int savedClipH;
    f32 pos[3];
    f32 mtx[12];
    u8* view;
    u8* model;
    void* viewMtx;
    f32 cloudT;
    f32 v;

    view = Camera_GetCurrentViewSlot();
    (*gSkyInterface)->getCurrentAmbientAndLightColors(
        &ambientRed, &ambientGreen, &ambientBlue, &lightRed, &lightGreen, &lightBlue);

    if (gCloudOverrideObject != NULL)
    {
        fn_8008DAE8((int)gCloudOverrideObject);
        model = Obj_GetActiveModel((int)gCloudOverrideObject);
        *(u16*)(model + 0x18) = *(u16*)(model + 0x18) & ~8;
        ((u8*)gCloudOverrideObject)[0x37] = 0xff;
        v = *(f32*)(view + 0xc);
        gCloudOverrideObject->anim.worldPosX = v;
        gCloudOverrideObject->anim.localPosX = v;
        v = *(f32*)(view + 0x10);
        gCloudOverrideObject->anim.worldPosY = v;
        gCloudOverrideObject->anim.localPosY = v;
        v = *(f32*)(view + 0x14);
        gCloudOverrideObject->anim.worldPosZ = v;
        gCloudOverrideObject->anim.localPosZ = v;
        fn_800412B8(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, (int)gCloudOverrideObject, 1);
        return;
    }

    if (shouldDrawClouds() == 0)
    {
        return;
    }

    if (lbl_8039AB28.upperCloudObj != NULL)
    {
        model = Obj_GetActiveModel((int)lbl_8039AB28.upperCloudObj);
        *(u16*)(model + 0x18) = *(u16*)(model + 0x18) & ~8;
        ((u8*)lbl_8039AB28.upperCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            lbl_8039AB28.upperCloudObj->anim.localPosX = gCloudOverridePositionX;
            lbl_8039AB28.upperCloudObj->anim.localPosY = lbl_803DF2C0 + gCloudOverridePositionY;
            lbl_8039AB28.upperCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            fn_8008DAE8((int)lbl_8039AB28.upperCloudObj);
            lbl_8039AB28.upperCloudObj->anim.localPosX = *(f32*)(view + 0xc);
            lbl_8039AB28.upperCloudObj->anim.localPosY = *(f32*)(view + 0x10);
            lbl_8039AB28.upperCloudObj->anim.localPosZ = *(f32*)(view + 0x14);
        }
        fn_800412B8(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, (int)lbl_8039AB28.upperCloudObj, 1);
    }

    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        if (isOvercast())
        {
            fn_8008DAE8((int)lbl_8039AB28.mainCloudObj);
        }
        model = Obj_GetActiveModel((int)lbl_8039AB28.mainCloudObj);
        *(u16*)(model + 0x18) = *(u16*)(model + 0x18) & ~8;
        ((u8*)lbl_8039AB28.mainCloudObj)[0x37] = 0xff;
        v = *(f32*)(view + 0xc);
        lbl_8039AB28.mainCloudObj->anim.worldPosX = v;
        lbl_8039AB28.mainCloudObj->anim.localPosX = v;
        v = lbl_803DF2C4 + *(f32*)(view + 0x10);
        lbl_8039AB28.mainCloudObj->anim.worldPosY = v;
        lbl_8039AB28.mainCloudObj->anim.localPosY = v;
        v = *(f32*)(view + 0x14);
        lbl_8039AB28.mainCloudObj->anim.worldPosZ = v;
        lbl_8039AB28.mainCloudObj->anim.localPosZ = v;
        lbl_8039AB28.mainCloudObj->anim.rotY = 0;
        fn_800412B8(ambientRed, ambientGreen, ambientBlue);
        objRender(a, b, c, d, (int)lbl_8039AB28.mainCloudObj, 1);

        fn_80060490(&clipX, &clipY, &clipW, &clipH);
        if (clipW > 0 && clipH > 0)
        {
            GXGetScissor(&savedClipX, &savedClipY, &savedClipW, &savedClipH);
            GXSetScissor(clipX, clipY, clipW, clipH);
            *(u16*)(*(int*)model + 2) = *(u16*)(*(int*)model + 2) | 0x2000;
            fn_8003BB7C(0x80);
            GXSetColorUpdate(0);
            objRender(a, b, c, d, (int)lbl_8039AB28.mainCloudObj, 1);
            *(u16*)(*(int*)model + 2) = *(u16*)(*(int*)model + 2) & ~0x2000;
            fn_8003BB7C(0);
            GXSetColorUpdate(1);
            GXSetScissor(savedClipX, savedClipY, savedClipW, savedClipH);
        }
    }

    cloudT = fn_8008ED88();
    if (cloudT > lbl_803DF2B4)
    {
        fn_8008EDE8(pos);
        pos[0] -= playerMapOffsetX;
        pos[2] -= playerMapOffsetZ;
        viewMtx = Camera_GetViewMatrix();
        GXSetCullMode(0);
        Camera_RebuildProjectionMatrix();
        GXClearVtxDesc();
        GXSetVtxDesc(9, 1);
        GXSetVtxDesc(0xd, 1);
        textureSetupFn_800799c0();
        gxTextureFn_800794e0();
        textRenderSetupFn_80079804();
        gxBlendFn_800789ac();
        PSMTXMultVec(viewMtx, pos, pos);
        PSMTXTrans(mtx, pos[0], pos[1], pos[2]);
        GXLoadPosMtxImm(mtx, 0);
        GXSetCurrentMtx(0);
        selectTexture(fn_8008912C(), 0);
        if (cloudT >= lbl_803DF2C8)
        {
            _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
        }
        else
        {
            _gxSetTevColor2(0x80, 0x80, 0xff, (int)(lbl_803DF2CC * (lbl_803DF2D0 * cloudT)));
        }
        if (getHudHiddenFrameCount() == 0)
        {
            *(f32*)&gCloudActionGlareQuadSize = randomGetRange(0x1f40, 0x2ee0);
        }
        GXBegin(0x80, 2, 4);
        v = -gCloudActionGlareQuadSize;
        GXPos3f32(v, v, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2B4, lbl_803DF2B4);
        GXPos3f32(gCloudActionGlareQuadSize, -gCloudActionGlareQuadSize, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2D4, lbl_803DF2B4);
        GXPos3f32(gCloudActionGlareQuadSize, gCloudActionGlareQuadSize, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2D4, lbl_803DF2D4);
        v = gCloudActionGlareQuadSize;
        GXPos3f32(-v, v, lbl_803DF2B4);
        GXTex2f32(lbl_803DF2B4, lbl_803DF2D4);
    }

    if (lbl_8039AB28.lowerCloudObj != NULL)
    {
        model = Obj_GetActiveModel((int)lbl_8039AB28.lowerCloudObj);
        *(u16*)(model + 0x18) = *(u16*)(model + 0x18) & ~8;
        ((u8*)lbl_8039AB28.lowerCloudObj)[0x37] = 0xff;
        if ((u32)gCloudOverridePositionValid != 0)
        {
            lbl_8039AB28.lowerCloudObj->anim.localPosX = gCloudOverridePositionX;
            lbl_8039AB28.lowerCloudObj->anim.localPosY = gCloudOverridePositionY - lbl_803DF2D8;
            lbl_8039AB28.lowerCloudObj->anim.localPosZ = gCloudOverridePositionZ;
        }
        else
        {
            fn_8008DAE8((int)lbl_8039AB28.lowerCloudObj);
            lbl_8039AB28.lowerCloudObj->anim.localPosX = *(f32*)(view + 0xc);
            lbl_8039AB28.lowerCloudObj->anim.localPosY = *(f32*)(view + 0x10);
            lbl_8039AB28.lowerCloudObj->anim.localPosZ = *(f32*)(view + 0x14);
        }
        objRender(a, b, c, d, (int)lbl_8039AB28.lowerCloudObj, 1);
    }
}

void cloudaction_func05(void)
{
    ObjTextureRuntimeSlot* tex;
    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        tex = objFindTexture(lbl_8039AB28.mainCloudObj, 0, 0);
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
    CloudEnvTbl* tbl = (CloudEnvTbl*)gCloudActionEnvTbl;
    int envState;

    envState = saveGameGetEnvState();
    if (state == NULL)
    {
        return;
    }
    if ((state[0x58] & 2) == 0)
    {
        return;
    }
    *(s16*)(envState + 0xa) = (s16)((s16) * (u16*)(state + 0x24) - 1);
    if ((state[0x59] & 1) == 0)
    {
        return;
    }
    lbl_803DB618[0] = lbl_803DB618[1];
    lbl_803DB618[1] = (u16)val;
    lbl_8039AB28.textureScrollStep = *(f32*)(state + 8) / lbl_803DF2DC;
    lbl_8039AB28.pad19 = 0;
    if ((*(volatile u8*)(state + 0x59) & 4) != 0)
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
            if (lbl_8039AB28.mainCloudAssetId != tbl->a[state[0x5d]])
            {
                if (lbl_8039AB28.mainCloudObj != NULL)
                {
                    Obj_FreeObject((int)lbl_8039AB28.mainCloudObj);
                }
                lbl_8039AB28.mainCloudObj = (GameObject*)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->a[state[0x5d]]), 4, -1, -1, 0);
                lbl_8039AB28.mainCloudAssetId = tbl->a[state[0x5d]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.mainCloudObj != NULL)
        {
            Obj_FreeObject((int)lbl_8039AB28.mainCloudObj);
            lbl_8039AB28.mainCloudObj = NULL;
        }
        lbl_8039AB28.mainCloudAssetId = 0;
    }
    if (state[0x5b] != 0)
    {
        if (state[0x5b] < 4)
        {
            if (lbl_8039AB28.upperCloudAssetId != tbl->b[state[0x5b]])
            {
                if (lbl_8039AB28.upperCloudObj != NULL)
                {
                    Obj_FreeObject((int)lbl_8039AB28.upperCloudObj);
                }
                lbl_8039AB28.upperCloudObj = (GameObject*)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->b[state[0x5b]]), 4, -1, -1, 0);
                lbl_8039AB28.upperCloudAssetId = tbl->b[state[0x5b]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.upperCloudObj != NULL)
        {
            Obj_FreeObject((int)lbl_8039AB28.upperCloudObj);
            lbl_8039AB28.upperCloudObj = NULL;
        }
        lbl_8039AB28.upperCloudAssetId = 0;
    }
    if (state[0x5a] != 0)
    {
        if (state[0x5a] < 5)
        {
            if (lbl_8039AB28.lowerCloudAssetId != tbl->c[state[0x5a]])
            {
                if (lbl_8039AB28.lowerCloudObj != NULL)
                {
                    Obj_FreeObject((int)lbl_8039AB28.lowerCloudObj);
                }
                lbl_8039AB28.lowerCloudObj = (GameObject*)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->c[state[0x5a]]), 4, -1, -1, 0);
                lbl_8039AB28.lowerCloudAssetId = tbl->c[state[0x5a]];
            }
        }
    }
    else
    {
        if (lbl_8039AB28.lowerCloudObj != NULL)
        {
            Obj_FreeObject((int)lbl_8039AB28.lowerCloudObj);
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
