/*
 * In-game C-menu (radial item ring) and Tricky HUD overlay rendering.
 *
 * cMenuSetItems / cMenuCountVisibleItems walk a placement-style item table (8
 * shorts per entry) gated by game bits, populating the parallel cMenu
 * arrays at lbl_803A87F0 (ids/words/state/flags/textures) and loading
 * per-item textures. The "useTricky" path filters entries through the
 * Tricky HUD item/action masks instead.
 *
 * The cMenuItemModelRenderFn / cMenuStaffModelRenderFn / cMenuRingModelRenderFn / cMenuRingIconRenderFn
 * callbacks are model render hooks that drive the GX colour/alpha
 * pipeline for menu/HUD models. drawTrickyHudOverlay draws the Tricky
 * action/item icons and the view-finder HUD. hudDrawCMenu renders the
 * three rotating menu objects through a dedicated camera view, fading
 * by selection. cMenuRotateFn_80124d80 advances the ring rotation and
 * computes the highlight fade (lbl_803DD8D4).
 */
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/cmenu_item_table.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "dolphin/gx/GXCull.h"
#include "main/camera.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/VF/vf_shared.h"
#include "dolphin/gx/GXTransform.h"

#define CMENU_OBJFLAG_PARENT_SLACK 0x1000

/* Number of slots in the parallel cMenu item arrays at lbl_803A87F0
   (ids/words/state/flags/textures); matches the s16 saved[64] snapshot. */
#define CMENU_ITEM_SLOT_COUNT 64

extern int FUN_8001792c();
extern u32 FUN_80051fc4();
extern u32 FUN_80052778();
extern u32 FUN_800528d0();
extern u32 FUN_80052904();
extern u32 FUN_80053078();
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern u32 FUN_8025c754();
extern u32 FUN_8025cce8();
extern u32 DAT_8031c130;
extern u32 DAT_803aa008;
extern u32 DAT_803aa024;
extern u32 DAT_803de3b8;
extern u32 DAT_803e2a90;
extern u32 DAT_803e2a94;
extern f32 FLOAT_803e2c90;
extern u8 lbl_803A87F0[];
extern CMenuItemDef gCMenuStaffAbilities[];
extern s16 gCMenuForcedSelIndex;
extern s8 gCMenuPreselectOwnedBit;
extern u16 yButtonState;
extern u16 yButtonItem;
extern s16 yButtonItemTextureId;
extern int gTrickyHudItemMask;
extern int gTrickyHudActionMask;
extern int getTrickyObject(void);
extern int getLoadedFileFlags(int flags);
extern u32 lbl_803E1E14;
extern int ObjModel_GetRenderOp(int model, int p);
extern void gxFn_80051fb8(void* a, int b, int c, void* d, int e, int f);
extern void GXSetBlendMode(GXBlendMode type, GXBlendFactor src_factor, GXBlendFactor dst_factor, GXLogicOp op);
extern void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);

extern void hudDrawTimedElement(int obj, void* p);

extern int getHudHiddenFrameCount(void);
extern void drawTexture(void* p, f32 a, f32 b, int c, int d);
extern u8 pauseMenuState;
extern int hudTextures[];
extern u8 lbl_803A9398[];
extern s16 gTrickyHudIconTextureIds[];
extern s16 gTrickyHudCachedIconIndex;
extern void* gTrickyHudCachedIconTexture;
extern f32 lbl_803E2018;
extern f32 lbl_803E2038;
extern f32 lbl_803E203C;
extern u32 lbl_803E1E10;
extern void* gCMenuRingIconTextures[7];
extern int gCMenuRingIconActiveFlags[7];
extern f32 lbl_803E2010;
extern void gxColorFn_80052764(void* p);
extern void Camera_SetCurrentViewIndex(int index);
extern void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll);
extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_ApplyFullViewport(void);
extern int Camera_IsViewYOffsetEnabled(void);
extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern void Camera_RebuildProjectionMatrix(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 fovY);
extern int Obj_GetActiveModel(int obj);
extern void objRender(int a, int b, int c, int d, int obj, int flag);

extern float mathCosf(float x);
extern s8 cMenuState;
extern s16 gCMenuScrollTimer;
extern s16 cMenuFadeCounter;
extern s16 lbl_803DD79A;
extern s16 lbl_803DD79C;
extern s16 lbl_803DD79E;
extern u16 lbl_803DBA30;
extern int gRenderModeObj;
extern int lbl_803DD7E0;
extern u8 gCMenuCurSection;
extern u8 lbl_803DD8B7;
extern u8 lbl_803DD8D4;
extern f32 lbl_803DBAA4;
extern f32 lbl_803DBAC4;
extern f32 lbl_803DBAC8;
extern int gCMenuRingFrontObjs[3];
extern int gCMenuRingObjs[3];
extern const f32 lbl_803E1E3C;
extern f32 lbl_803E1E40;
extern f32 lbl_803E1E68;
extern const f32 lbl_803E1E94;
extern f32 lbl_803E1EC4;
extern const f32 lbl_803E1EC8;
extern f32 lbl_803E1F34;
extern f32 lbl_803E201C;
extern f32 lbl_803E2020;
extern f32 lbl_803E2024;
extern f64 lbl_803E2028;
extern f64 lbl_803E2030;

int cMenuSetItems(s16* items, char useTricky)
{
    s16* w2;
    s16* stP;
    int active;
    s16* w3;
    s16* src;
    u8* w4;
    s16* ids;
    void** texW;
    int* wordP;
    u8* base;
    s16* dst;
    u8* flP;
    int halfOff;
    s16* idsW2;
    int count;
    s16* w1;
    int wordOff;
    void** texP2;
    int i;
    s16 saved[CMENU_ITEM_SLOT_COUNT];

    base = lbl_803A87F0;
    ids = (s16*)(base + 0x948);
    w1 = ids;
    dst = saved;
    w2 = dst;
    stP = (s16*)(base + 0x548);
    w3 = stP;
    flP = base + 0x448;
    w4 = flP;
    for (i = 0; i < CMENU_ITEM_SLOT_COUNT; i++)
    {
        *w2 = *w1;
        *w1 = -1;
        halfOff = 0;
        *w3 = halfOff;
        *w4 = 1;
        w1++;
        w2++;
        w3++;
        w4++;
    }
    count = 0;
    wordOff = 0;
    wordP = (int*)(base + 0x848);
    *wordP = -1;
    if (useTricky == 0)
    {
        gCMenuForcedSelIndex = -1;
        for (src = items; *src > -1; src += 8)
        {
            active = GameBit_Get(*src);
            if (active != 0)
            {
                if (items == (s16*)gCMenuStaffAbilities)
                {
                    if (src[1] < 0 || GameBit_Get(src[1]) == 0)
                    {
                        *(s16*)(base + halfOff + 0x948) = src[3];
                        *(int*)(base + wordOff + 0x848) = src[0];
                        *(int*)(base + wordOff + 0x748) = src[2];
                        *(int*)(base + wordOff + 0x648) = src[1];
                        *(u8*)(base + count + 0x448) = active;
                        *(s16*)(base + halfOff + 0x548) = src[6];
                        *(s16*)(base + halfOff + 0x5c8) = src[5];
                        *(u8*)(base + count + 0x508) = *(u8*)(src + 7);
                        *(u8*)(base + count + 0x4c8) = ((u8*)src)[0xf];
                        if (src[2] < 0 || GameBit_Get(src[2]) == 0)
                        {
                            *(u8*)(count + 0x488 + base) = 1;
                        }
                        else
                        {
                            *(u8*)(count + 0x488 + base) = 0;
                        }
                        count++;
                        wordOff += 4;
                        halfOff += 2;
                    }
                }
                else if (src[1] < 0 || GameBit_Get(src[1]) == 0)
                {
                    if (gCMenuPreselectOwnedBit != 0 && gCMenuPreselectOwnedBit == *src)
                    {
                        gCMenuForcedSelIndex = count;
                    }
                    *(s16*)(base + halfOff + 0x948) = src[3];
                    *(int*)(base + wordOff + 0x848) = src[0];
                    *(int*)(base + wordOff + 0x748) = src[2];
                    *(int*)(base + wordOff + 0x648) = src[1];
                    *(u8*)(base + count + 0x448) = active;
                    *(s16*)(base + halfOff + 0x548) = src[6];
                    *(s16*)(base + halfOff + 0x5c8) = src[5];
                    *(u8*)(base + count + 0x508) = *(u8*)(src + 7);
                    *(u8*)(base + count + 0x4c8) = ((u8*)src)[0xf];
                    if (src[2] < 0 || GameBit_Get(src[2]) == 0)
                    {
                        *(u8*)(count + 0x488 + base) = 1;
                    }
                    else
                    {
                        *(u8*)(count + 0x488 + base) = 0;
                    }
                    count++;
                    wordOff += 4;
                    halfOff += 2;
                }
            }
        }
    }
    else
    {
        int itemMask;
        int actionMask;
        int yItem;
        s16* idsW;
        s16* aW;
        u8* cW;
        u8* dW;
        u8* eW;

        getTrickyObject();
        itemMask = gTrickyHudItemMask;
        if (itemMask != -1)
        {
            src = items;
            idsW = ids;
            aW = (s16*)(base + 0x5c8);
            cW = base + 0x508;
            dW = base + 0x4c8;
            eW = base + 0x488;
            actionMask = gTrickyHudActionMask;
            yItem = yButtonItem;
            for (; *src > -1; src += 8)
            {
                if ((actionMask & *src) != 0)
                {
                    *idsW = src[3];
                    *flP = 1;
                    *wordP = src[2];
                    *stP = src[6];
                    *aW = src[5];
                    *cW = *(u8*)(src + 7);
                    *dW = ((u8*)src)[0xf];
                    if ((itemMask & *src) != 0)
                    {
                        *eW = 1;
                    }
                    else
                    {
                        *eW = 0;
                    }
                    idsW++;
                    flP++;
                    wordP++;
                    stP++;
                    aW++;
                    cW++;
                    dW++;
                    eW++;
                    count++;
                }
                else if (yButtonState == 2 && yItem == src[2])
                {
                    yButtonState = 0;
                    yButtonItemTextureId = -1;
                }
            }
        }
        else
        {
            if (yButtonState == 2)
            {
                yButtonState = 0;
                yButtonItemTextureId = -1;
            }
        }
    }
    i = 0;
    idsW2 = ids;
    texP2 = (void**)(base + 0x9c8);
    texW = texP2;
    do
    {
        if (*dst > -1 && *dst != *idsW2 && *texW != 0)
        {
            textureFree(*texW);
            *texW = 0;
        }
        dst++;
        idsW2++;
        texW++;
        i++;
    }
    while (i < CMENU_ITEM_SLOT_COUNT);
    if (getLoadedFileFlags(0) == 0)
    {
        i = 0;
        do
        {
            if (*ids > -1 && *texP2 == 0)
            {
                *texP2 = textureLoadAsset(*ids);
            }
            ids++;
            texP2++;
            i++;
        }
        while (i < CMENU_ITEM_SLOT_COUNT);
    }
    return count;
}

#pragma scheduling on
#pragma peephole on
int cMenuCountVisibleItems(s16* table, char mode)
{
    u32 bitVal;
    int count;
    s16* entry;

    count = 0;
    entry = table;
    if (mode == 0)
    {
        for (; -1 < *entry; entry += 8)
        {
            bitVal = GameBit_Get((int)*entry);
            if (bitVal != 0)
            {
                if (table == (short*)&DAT_8031c130)
                {
                    if ((entry[2] < 0) || (bitVal = GameBit_Get((int)entry[2]), bitVal == 0))
                    {
                        count++;
                    }
                }
                else if (((entry[1] < 0) || (bitVal = GameBit_Get((int)entry[1]), bitVal == 0)) &&
                    ((entry[2] < 0 || (bitVal = GameBit_Get((int)entry[2]), bitVal == 0))))
                {
                    count++;
                }
            }
        }
    }
    else if (0 < DAT_803de3b8)
    {
        for (; -1 < *table; table = table + 8)
        {
            if ((DAT_803de3b8 != 0xffffffff) && ((DAT_803de3b8 & (int)*table) != 0))
            {
                count++;
            }
        }
    }
    return count;
}

#pragma scheduling off
#pragma peephole off
void cMenuNullRenderFn(u64 param_1, f64 param_2, f64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
}

#pragma scheduling on
#pragma peephole on
int cMenuItemModelRenderFn(int shader, int* block, int idx)
{
    int rec;
    u32 texHandle;
    u32 colorWord;

    colorWord = DAT_803e2a94;
    rec = FUN_8001792c(*block, idx);
    FUN_80052904();
    colorWord = ((u32)(((u32)(colorWord >> 8) << 8) | (u8)(*(u8*)(shader + 0x37))));
    texHandle = FUN_80053078(*(u32*)(rec + 0x24));
    FUN_80051fc4(texHandle, 0, 0, &colorWord, 0, 1);
    FUN_800528d0();
    FUN_8025cce8(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    FUN_8025c754(7, 0, 0, 7, 0);
    return 1;
}

int cMenuStaffModelRenderFn(int shader, int* block, int idx)
{
    int level;
    int rec;
    u32 colorWord;
    u32* tabA;
    u32* tabB;

    colorWord = DAT_803e2a90;
    rec = FUN_8001792c(*block, idx);
    rec = *(u8*)(rec + 0x29) - 1;
    FUN_80052904();
    if ((-1 < rec) && (rec < 7))
    {
        tabA = &DAT_803aa024;
        tabB = &DAT_803aa008;
        if (tabA[rec] != 0)
        {
            if (tabB[rec] == 0)
            {
                level = (int)(FLOAT_803e2c90 *
                    (f32)((double)(u32) * (u8*)(shader + 0x37)));
                colorWord = ((u32)(((u32)(colorWord >> 8) << 8) | (u8)(level)));
            }
            else
            {
                colorWord = ((u32)(((u32)(colorWord >> 8) << 8) | (u8)(*(u8*)(shader + 0x37))));
            }
            FUN_80051fc4(tabA[rec], 0, 0, &colorWord, 0, 1);
        }
        else
        {
            FUN_80052778((char*)&colorWord + 1);
        }
    }
    else
    {
        FUN_80052778((char*)&colorWord + 1);
    }
    FUN_800528d0();
    FUN_8025cce8(1, 4, 5, 5);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    FUN_8025c754(7, 0, 0, 7, 0);
    return 1;
}

#pragma scheduling off
#pragma peephole off
int cMenuRingModelRenderFn(int obj, int param2, int param3)
{
    int renderOp;
    u8 cfg[4];
    *(u32*)cfg = lbl_803E1E14;
    renderOp = ObjModel_GetRenderOp(*(int*)param2, param3);
    resetLotsOfRenderVars();
    cfg[3] = *(u8*)(obj + 0x37);
    gxFn_80051fb8(textureIdxToPtr(*(int*)(renderOp + 0x24)), 0, 0, cfg, 0, 1);
    textureFn_800528bc();
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return 1;
}

void drawTrickyHudOverlay(int obj)
{
    int player;
    int tricky;
    int iconIndex;
    player = (int)Obj_GetPlayerObject();
    tricky = getTrickyObject();
    GXSetScissor(0, 0, 0x280, 0x1e0);
    hudDrawTimedElement(obj, lbl_803A9398);
    if ((void*)tricky != 0)
    {
        gTrickyHudItemMask = (*(int (**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x24))(tricky);
        gTrickyHudActionMask = (*(int (**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x20))(tricky);
    }
    else
    {
        gTrickyHudItemMask = 0;
        gTrickyHudActionMask = 0;
    }
    drawViewFinderHud();
    if ((*gCameraInterface)->getMode() != 0x44 &&
        (((GameObject*)player)->objectFlags & CMENU_OBJFLAG_PARENT_SLACK) == 0 &&
        pauseMenuState == 0 &&
        (void*)tricky != 0 &&
        getHudHiddenFrameCount() == 0)
    {
        (*(int (**)(int, int*))(*(int*)(*(int*)(tricky + 0x68)) + 0x48))(tricky, &iconIndex);
        if (gTrickyHudCachedIconTexture != 0)
        {
            if (gTrickyHudCachedIconIndex != iconIndex)
            {
                ((void (*)(void*))textureFree)(gTrickyHudCachedIconTexture);
                gTrickyHudCachedIconIndex = -1;
                gTrickyHudCachedIconTexture = 0;
            }
        }
        if (gTrickyHudCachedIconTexture == 0)
        {
            if (iconIndex > -1)
            {
                if (gTrickyHudIconTextureIds[iconIndex] != -1)
                {
                    gTrickyHudCachedIconTexture = textureLoadAsset(gTrickyHudIconTextureIds[iconIndex]);
                }
            }
        }
        gTrickyHudCachedIconIndex = iconIndex;
        if (gTrickyHudCachedIconTexture != 0)
        {
            drawTexture((void*)hudTextures[0x1d], lbl_803E2018, lbl_803E2038, 0xff, 0x100);
            drawTexture(gTrickyHudCachedIconTexture, lbl_803E2018, lbl_803E203C, 0xff, 0x80);
        }
    }
}

#pragma peephole on
int cMenuRingIconRenderFn(int obj, int param2, int param3)
{
    int idx;
    void* tex;
    u8 cfg[4];
    *(u32*)cfg = lbl_803E1E10;
    idx = *(u8*)(ObjModel_GetRenderOp(*(int*)param2, param3) + 0x29) - 1;
    resetLotsOfRenderVars();
    if (idx >= 0 && idx <= 6 && (tex = gCMenuRingIconTextures[idx]) != 0)
    {
        if (gCMenuRingIconActiveFlags[idx] != 0)
        {
            cfg[3] = *(u8*)(obj + 0x37);
        }
        else
        {
            int v = (int)(lbl_803E2010 * (f32)(u32) * (u8*)(obj + 0x37));
            cfg[3] = v;
        }
        gxFn_80051fb8(tex, 0, 0, cfg, 0, 1);
    }
    else
    {
        cfg[3] = 0;
        gxColorFn_80052764(cfg);
    }
    textureFn_800528bc();
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(0, 7, 0);
    gxSetPeControl_ZCompLoc_(0);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    return 1;
}

#pragma peephole off
void hudDrawCMenu(int p1, int p2, int p3)
{
    u8 slot;
    int j;
    int sel;
    int model;
    int i;
    f32 sx;
    f32 sy;
    u8 used[4];
    f32 vals[3];

    Camera_GetCurrentViewSlot();
    slot = 0;
    switch (cMenuState)
    {
    case 2:
        slot = 0;
        break;
    case 3:
        slot = 1;
        break;
    case 4:
        slot = 2;
        break;
    }
    *(f32*)(gCMenuRingFrontObjs[slot] + 0x10) =
        lbl_803E1E40 + (f32)(-gCMenuScrollTimer * lbl_803DBA30) / lbl_803E201C;
    sy = lbl_803DBAC8;
    sx = lbl_803DBAC4;
    lbl_803DBAA4 = Camera_GetFovY();
    Camera_SetFovY(lbl_803E2020);
    Camera_SetCurrentViewIndex(1);
    lbl_803DD7E0 = Camera_IsViewYOffsetEnabled();
    Camera_DisableViewYOffset();
    {
        f32 small = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(small, small, small);
    }
    Camera_SetCurrentViewRotation(0x8000, 0, 0);
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    GXSetViewport(sx - lbl_803E1F34, sy - lbl_803E2024, (f32)(u32) * (u16*)(gRenderModeObj + 4),
                  (f32)(u32) * (u16*)(gRenderModeObj + 8), lbl_803E1E3C, lbl_803E1E68);
    i = 0;
    do
    {
        used[i] = 0;
        vals[i] = mathCosf(lbl_803E1EC8 * (f32) * (s16*)gCMenuRingObjs[i] / lbl_803E1E94);
        i++;
    }
    while (i < 3);
    j = 0;
    do
    {
        f32 best = lbl_803E1EC4;
        sel = -1;
        if (used[0] == 0 && vals[0] < best)
        {
            best = vals[0];
            sel = 0;
        }
        if (used[1] == 0 && vals[1] < best)
        {
            best = vals[1];
            sel = 1;
        }
        if (used[2] == 0 && vals[2] < best)
        {
            best = vals[2];
            sel = 2;
        }
        if (sel == -1)
        {
            break;
        }
        model = Obj_GetActiveModel(gCMenuRingObjs[sel]);
        *(u16*)(model + 0x18) &= ~8;
        *(u8*)(gCMenuRingObjs[sel] + 0x37) = cMenuFadeCounter;
        model = Obj_GetActiveModel(gCMenuRingFrontObjs[sel]);
        *(u16*)(model + 0x18) &= ~8;
        *(u8*)(gCMenuRingFrontObjs[sel] + 0x37) = cMenuFadeCounter * lbl_803DD8D4 / 0xff;
        if (best > lbl_803E1E3C)
        {
            objRender(p1, p2, p3, 0, gCMenuRingObjs[sel], 1);
            GXSetScissor(0, 0x79, 0x280, 0x95);
            objRender(p1, p2, p3, 0, gCMenuRingFrontObjs[sel], 1);
            GXSetScissor(0, 0, 0x280, 0x1e0);
        }
        else
        {
            objRender(p1, p2, p3, 0, gCMenuRingObjs[sel], 1);
        }
        used[sel] = 1;
        j++;
    }
    while (j < 3);
    Camera_SetCurrentViewIndex(0);
    if (lbl_803DD7E0 != 0)
    {
        Camera_EnableViewYOffset();
    }
    Camera_UpdateViewMatrices();
    Camera_SetFovY(lbl_803DBAA4);
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
}

void cMenuRotateFn_80124d80(void)
{
    u16 uend;
    s16 diff;
    s16 step;
    int cur;
    s16 diff2;
    s16 curd;
    s16 d1;
    s16 d2;
    s16 d3;
    s16 best;
    s16 r;
    int t1;
    int t5;
    s16 rot;

    step = (s16)(lbl_803DD79A * (framesThisStep * 1000));
    if (step != 0)
    {
        uend = lbl_803DD79E;
        diff = (s16)(lbl_803DD79C - uend);
        if (diff > 0x8000)
        {
            diff = (s16)(diff - 0xFFFF);
        }
        if (diff < -0x8000)
        {
            diff = (s16)(diff + 0xFFFF);
        }
        t5 = (step < 0) ? -step : step;
        if (((diff < 0) ? -diff : diff) <= t5)
        {
            lbl_803DD79C = lbl_803DD79E;
            lbl_803DD79A = 0;
        }
        else
        {
            lbl_803DD79C += step;
        }
        cur = lbl_803DD79C;
        diff2 = (s16)(cur - uend);
        if (diff2 > 0x8000)
        {
            diff2 = (s16)(diff2 - 0xFFFF);
        }
        if (diff2 < -0x8000)
        {
            diff2 = (s16)(diff2 + 0xFFFF);
        }
        t1 = diff2;
        if (t1 < 0)
        {
            t1 = -t1;
        }
        if (t1 <= 0x2aaa)
        {
            gCMenuCurSection = lbl_803DD8B7;
        }
        rot = cur;
        *(s16*)gCMenuRingObjs[0] = rot;
        *(s16*)gCMenuRingFrontObjs[0] = rot;
        rot += 0x5555;
        *(s16*)gCMenuRingObjs[1] = rot;
        *(s16*)gCMenuRingFrontObjs[1] = rot;
        rot += 0x5555;
        *(s16*)gCMenuRingObjs[2] = rot;
        *(s16*)gCMenuRingFrontObjs[2] = rot;
        curd = lbl_803DD79C;
        d1 = curd;
        if (curd > 0x8000)
        {
            d1 = (s16)(curd - 0xFFFF);
        }
        if (d1 < -0x8000)
        {
            d1 = (s16)(d1 + 0xFFFF);
        }
        d2 = (s16)(curd - 0x5555);
        if (d2 > 0x8000)
        {
            d2 = (s16)(d2 - 0xFFFF);
        }
        if (d2 < -0x8000)
        {
            d2 = (s16)(d2 + 0xFFFF);
        }
        d3 = (s16)(curd - 0xAAAA);
        if (d3 > 0x8000)
        {
            d3 = (s16)(d3 - 0xFFFF);
        }
        if (d3 < -0x8000)
        {
            d3 = (s16)(d3 + 0xFFFF);
        }
        best = ((d1 < 0 ? -d1 : d1) < (d2 < 0 ? -d2 : d2))
                   ? (d1 < 0 ? -d1 : d1)
                   : (d2 < 0 ? -d2 : d2);
        best = (best < (d3 < 0 ? -d3 : d3)) ? best : (d3 < 0 ? -d3 : d3);
        r = (s16)(int) - (lbl_803E2030 * best - lbl_803E2028);
        lbl_803DD8D4 = (r > 0) ? r : 0;
    }
    cur = lbl_803DD79C;
    rot = cur;
    *(s16*)gCMenuRingObjs[0] = rot;
    *(s16*)gCMenuRingFrontObjs[0] = rot;
    rot += 0x5555;
    *(s16*)gCMenuRingObjs[1] = rot;
    *(s16*)gCMenuRingFrontObjs[1] = rot;
    rot += 0x5555;
    *(s16*)gCMenuRingObjs[2] = rot;
    *(s16*)gCMenuRingFrontObjs[2] = rot;
    curd = lbl_803DD79C;
    d1 = curd;
    if (curd > 0x8000)
    {
        d1 = (s16)(curd - 0xFFFF);
    }
    if (d1 < -0x8000)
    {
        d1 = (s16)(d1 + 0xFFFF);
    }
    d2 = (s16)(curd - 0x5555);
    if (d2 > 0x8000)
    {
        d2 = (s16)(d2 - 0xFFFF);
    }
    if (d2 < -0x8000)
    {
        d2 = (s16)(d2 + 0xFFFF);
    }
    d3 = (s16)(curd - 0xAAAA);
    if (d3 > 0x8000)
    {
        d3 = (s16)(d3 - 0xFFFF);
    }
    if (d3 < -0x8000)
    {
        d3 = (s16)(d3 + 0xFFFF);
    }
    best = ((d1 < 0 ? -d1 : d1) < (d2 < 0 ? -d2 : d2))
               ? (d1 < 0 ? -d1 : d1)
               : (d2 < 0 ? -d2 : d2);
    best = (best < (d3 < 0 ? -d3 : d3)) ? best : (d3 < 0 ? -d3 : d3);
    r = (s16)(int) - (lbl_803E2030 * best - lbl_803E2028);
    lbl_803DD8D4 = (r > 0) ? r : 0;
}
