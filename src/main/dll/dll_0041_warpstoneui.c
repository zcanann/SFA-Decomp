/*
 * warpstoneUI (DLL 0x41) - the warpstone screen-overlay UI.
 *
 * State machine driven by warpstoneUIState (a UI page id); WarpstoneUI_showUI
 * dispatches on it each frame:
 *   1        warpstone texture + intro text (gameText 0x37C..0x37E)
 *   2,3,5    shared status line (gameText 0x3DD)
 *   4        the level-warp menu: builds the selectable list from the six
 *            warpstone game bits (fn_801343CC over gWarpStoneUiEntryTable) and drives
 *            the gTitleMenuLinkInterface vtable; a selection issues a map act
 *            on map 0x42.
 * WarpstoneUI_frameStart ramps the overlay opacity (lbl_803DD97C) in/out and
 * clamps it; WarpstoneUI_initialise loads the two textures, WarpstoneUI_release
 * frees them. Drawn alpha follows lbl_803DD97C throughout.
 */
#include "main/texture.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/dll_0000_gameui.h"
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShow(int a);
extern void gameTextFn_80016810(int a, int b, int c);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);

extern u8 warpstoneUIState;
extern void* lbl_803DD984;
extern void* lbl_803DD980;
extern f32 lbl_803DD97C;
extern int gWarpStoneUiMenuActive;
extern f32 lbl_803E22E0;
extern f32 lbl_803E22D8;
extern f32 lbl_803E22DC;
extern f32 timeDelta;
extern int lbl_803DBBF8;
extern int lbl_803DBBFC;
extern int lbl_803DBC00;
extern int lbl_803DBC04;

typedef struct
{
    s16 bit;
    u8 mapAct;
    u8 b3; /* unused/padding */
} WarpstoneEntry;

/* gWarpStoneUiEntryTable holds one WarpstoneEntry per warpstone destination
   (data symbol size 0x18 / sizeof(WarpstoneEntry) == 6). */
#define WARPSTONE_UI_ENTRY_COUNT 6

extern u8 gWarpStoneUiMenuItemTemplates[];
extern u8 gWarpStoneUiMenuItems[];
extern WarpstoneEntry gWarpStoneUiEntryTable[];
extern int gWarpStoneUiSelectedIndices[];
extern int* gTitleMenuLinkInterface;

#pragma scheduling off
#pragma peephole off
int fn_801343CC(u8* src, u8* dst, u8* ids, int count, int* out)
{
    int k;
    u8* idp;
    u8* lastDst;
    int yoff;
    int n;

    lastDst = NULL;
    n = 0;
    k = 0;
    idp = ids;
    for (; k < count; k++)
    {
        if ((u32)GameBit_Get(*(s16*)idp) != 0)
        {
            n++;
        }
        idp += 4;
    }
    n = (count - n) * 0x2a / 2 + 0x52;
    k = 0;
    idp = ids;
    yoff = n;
    for (n = 0; n < count; n++)
    {
        if ((u32)GameBit_Get(*(s16*)idp) != 0)
        {
            memcpy(dst, src, 0x3c);
            lastDst = dst;
            *(s16*)(dst + 6) = yoff;
            *(s8*)(dst + 0x1a) = (s8)(k - 1);
            *(s8*)(dst + 0x1b) = (s8)(k + 1);
            *out = n;
            out++;
            dst += 0x3c;
            yoff += 0x2a;
            k++;
        }
        idp += 4;
        src += 0x3c;
    }
    if (lastDst != NULL)
    {
        *(s8*)(lastDst + 0x1b) = -1;
    }
    return k;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void WarpstoneUI_setState(int val) { warpstoneUIState = val; }
#pragma peephole reset

#pragma scheduling off
void WarpstoneUI_showUI(int arg)
{
    int sel;
    int idx;
    int n;

    CMenu_SetFadeCounter(0);
    switch (warpstoneUIState)
    {
    case 2:
    case 3:
    case 5:
        gameTextSetColor(0xff, 0xff, 0xff, lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBBF8);
        break;
    case 1:
        drawTexture(lbl_803DD980, (f32)(int)(lbl_803DBBFC - 0x1d), (f32)(int)(lbl_803DBC00 + 0xd),
                    lbl_803DD97C, 0xff);
        gameTextSetColor(0xff, 0xff, 0xff, lbl_803DD97C);
        gameTextShow(0x37c);
        gameTextShow(0x37d);
        gameTextShow(0x37e);
        break;
    case 4:
        gameTextSetColor(0xff, 0xff, 0xff, lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBC04);
        if (gWarpStoneUiMenuActive == 0)
        {
            n = fn_801343CC(gWarpStoneUiMenuItemTemplates, gWarpStoneUiMenuItems, (u8*)gWarpStoneUiEntryTable, WARPSTONE_UI_ENTRY_COUNT, gWarpStoneUiSelectedIndices);
            (**(void (**)(u8*, int, int, int, int, int, int, int, int, int, int, int))
                    ((char*)(*gTitleMenuLinkInterface) + 4))
                (gWarpStoneUiMenuItems, n, 0, 0, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
            gWarpStoneUiMenuActive = 1;
        }
        sel = (**(int (**)(void))((char*)(*gTitleMenuLinkInterface) + 0xc))();
        idx = (**(int (**)(void))((char*)(*gTitleMenuLinkInterface) + 0x14))();
        if (sel > 0)
        {
            (*gMapEventInterface)->setMapAct(0x42, gWarpStoneUiEntryTable[gWarpStoneUiSelectedIndices[idx]].mapAct);
        }
        (**(void (**)(int))((char*)(*gTitleMenuLinkInterface) + 0x10))(arg);
        break;
    }
    if (gWarpStoneUiMenuActive != 0 && warpstoneUIState != 4)
    {
        (**(void (**)(void))((char*)(*gTitleMenuLinkInterface) + 8))();
        gWarpStoneUiMenuActive = 0;
    }
}
#pragma scheduling reset

void WarpstoneUI_frameEnd(void)
{
}

#pragma scheduling off
int WarpstoneUI_frameStart(void)
{
    f32 v;
    if (warpstoneUIState == 0)
    {
        lbl_803DD97C = lbl_803DD97C - (lbl_803E22D8 * timeDelta);
    }
    else
    {
        lbl_803DD97C = lbl_803DD97C + (lbl_803E22D8 * timeDelta);
    }
    v = lbl_803DD97C;
    if (v > *(f32*)&lbl_803E22DC)
    {
        lbl_803DD97C = lbl_803E22DC;
    }
    else if (v < *(f32*)&lbl_803E22E0)
    {
        lbl_803DD97C = lbl_803E22E0;
    }
    return 0;
}
#pragma scheduling reset

void WarpstoneUI_release(void)
{
    textureFree(lbl_803DD984);
    textureFree(lbl_803DD980);
}

#pragma scheduling off
void WarpstoneUI_initialise(void)
{
    lbl_803DD984 = textureLoadAsset(0x4FA);
    lbl_803DD980 = textureLoadAsset(0x5E3);
    lbl_803DD97C = lbl_803E22E0;
}
#pragma scheduling reset
