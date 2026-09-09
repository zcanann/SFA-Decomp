#include "main/dll/dll_0041_warpstoneui.h"
#include "main/texture.h"
#include "string.h"
#include "track/intersect_hud_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_api.h"
#include "main/textrender_api.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/frame_timing.h"
#include "main/resource.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_003C_link.h"
#include "main/dll/FRONT/title_menu.h"

int gWarpStoneUiTextPosY = 0x140;
#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
int gWarpStoneUiTextureX = 310;
int gWarpStoneUiTextureY = 270;
#else
int gWarpStoneUiTextureX = 320;
int gWarpStoneUiTextureY = 285;
#endif
int gWarpStoneUiMenuTextPosY = 0x140;

#define WARPSTONEUI_TEXTURE_A 0x4FA
#define WARPSTONEUI_TEXTURE_B 0x5E3

#define WARPSTONE_UI_ENTRY_COUNT 6

#define WARPSTONEUI_MAPEVENT_KRAZOA 0x42

u8 warpstoneUIState[8];
Texture* gWarpStoneUiTextureA;
Texture* gWarpStoneUiTexture;
f32 gWarpStoneUiFadeAlpha;
int gWarpStoneUiMenuActive;
extern TitleMenuTextEntry gWarpStoneUiMenuItemTemplates[];

TitleMenuTextEntry gWarpStoneUiMenuItems[WARPSTONE_UI_ENTRY_COUNT];
WarpstoneEntry gWarpStoneUiEntryTable[WARPSTONE_UI_ENTRY_COUNT] = {
    {0x0ABA, 1, 0}, {0x0ABD, 4, 0}, {0x0ABE, 5, 0}, {0x0ABF, 6, 0}, {0x0AC0, 7, 0}, {0x0AC1, 8, 0},
};
int gWarpStoneUiSelectedIndices[0x6];

static int WarpstoneUI_getMenuItems(const TitleMenuTextEntry* templates, TitleMenuTextEntry* items,
                                    const WarpstoneEntry* entries, int count, int* selectedIndices) {
    int yStart;
    TitleMenuTextEntry* lastDst;
    int slot;
    int entry;

    lastDst = NULL;
    slot = 0;
    entry = 0;
    for (; entry < count; entry++) {
        if (mainGetBit(entries[entry].bit) != 0) {
            slot++;
        }
    }
    yStart = (count - slot) * 0x2a / 2 + 0x52;
    slot = 0;
    entry = slot;
    for (; entry < count; entry++) {
        if (mainGetBit(entries[entry].bit) != 0) {
            memcpy(&items[slot], &templates[entry], sizeof(TitleMenuTextEntry));
            lastDst = &items[slot];
            items[slot].textTop = yStart + slot * 0x2a;
            items[slot].upLink = slot - 1;
            items[slot].downLink = slot + 1;
            *selectedIndices++ = entry;
            slot++;
        }
    }
    if (lastDst != NULL) {
        lastDst->downLink = -1;
    }
    return slot;
}

void WarpstoneUI_setState(int val) {
    warpstoneUIState[0] = val;
}

void WarpstoneUI_showUI(int arg) {
    int sel;
    int idx;
    int itemCount;

    CMenu_SetFadeCounter(0);
    switch (warpstoneUIState[0]) {
    case 2:
    case 3:
    case 5:
        gameTextSetColor(0xff, 0xff, 0xff, gWarpStoneUiFadeAlpha);
        gameTextShowAt(0x3dd, 200, gWarpStoneUiTextPosY);
        break;
    case 1:
        drawTexture(gWarpStoneUiTexture, (f32)(int)(gWarpStoneUiTextureX - 0x1d),
                    (f32)(int)(gWarpStoneUiTextureY + 0xd), gWarpStoneUiFadeAlpha, 0xff);
        gameTextSetColor(0xff, 0xff, 0xff, gWarpStoneUiFadeAlpha);
        gameTextShow(0x37c);
        gameTextShow(0x37d);
        gameTextShow(0x37e);
        break;
    case 4:
        gameTextSetColor(0xff, 0xff, 0xff, gWarpStoneUiFadeAlpha);
        gameTextShowAt(0x3dd, 200, gWarpStoneUiMenuTextPosY);
        if (gWarpStoneUiMenuActive == 0) {
            itemCount =
                WarpstoneUI_getMenuItems(gWarpStoneUiMenuItemTemplates, gWarpStoneUiMenuItems, gWarpStoneUiEntryTable,
                                         WARPSTONE_UI_ENTRY_COUNT, gWarpStoneUiSelectedIndices);
            gTitleMenuLinkInterface->vtable->setup(gWarpStoneUiMenuItems, itemCount, 0, NULL, 0, 0, 0x14, 200, 0xff,
                                                   0xff, 0xff, 0xff);
            gWarpStoneUiMenuActive = 1;
        }
        sel = gTitleMenuLinkInterface->vtable->update();
        idx = gTitleMenuLinkInterface->vtable->getSelected();
        if (sel > 0) {
            (*gMapEventInterface)
                ->setMapAct(WARPSTONEUI_MAPEVENT_KRAZOA,
                            gWarpStoneUiEntryTable[gWarpStoneUiSelectedIndices[idx]].mapAct);
        }
        gTitleMenuLinkInterface->vtable->render(arg);
        break;
    }
    if (gWarpStoneUiMenuActive != 0 && warpstoneUIState[0] != 4) {
        gTitleMenuLinkInterface->vtable->free();
        gWarpStoneUiMenuActive = 0;
    }
}

void WarpstoneUI_frameEnd(void) {
}

int WarpstoneUI_frameStart(void) {
    f32 alpha;
    if (warpstoneUIState[0] == 0) {
        gWarpStoneUiFadeAlpha -= (8.0f * timeDelta);
    } else {
        gWarpStoneUiFadeAlpha += (8.0f * timeDelta);
    }
    alpha = gWarpStoneUiFadeAlpha;
    if (alpha > 255.0f) {
        gWarpStoneUiFadeAlpha = 255.0f;
    } else if (alpha < 0.0f) {
        gWarpStoneUiFadeAlpha = 0.0f;
    }
    return 0;
}

void WarpstoneUI_release(void) {
    textureFree(gWarpStoneUiTextureA);
    textureFree(gWarpStoneUiTexture);
}

void WarpstoneUI_initialise(void) {
    gWarpStoneUiTextureA = textureLoadAsset(WARPSTONEUI_TEXTURE_A);
    gWarpStoneUiTexture = textureLoadAsset(WARPSTONEUI_TEXTURE_B);
    gWarpStoneUiFadeAlpha = 0.0f;
}

TitleMenuTextEntry gWarpStoneUiMenuItemTemplates[WARPSTONE_UI_ENTRY_COUNT] = {
    {0x34C, 0x2F, 350, 82, 0, 400, 52, {0, 0}, -1, 280, 0x0280, {0, 0}, -1, 1, -1, -1, -1, {0}, 0, {0, 0, 0}},
    {0x34D, 0x30, 350, 208, 0, 400, 160, {0, 0}, -1, 280, 0x0280, {0, 0}, 2, 4, -1, -1, -1, {0}, 0, {0, 0, 0}},
    {0x429, 0x31, 350, 250, 0, 400, 160, {0, 0}, -1, 280, 0x0280, {0, 0}, 3, 5, -1, -1, -1, {0}, 0, {0, 0, 0}},
    {0x34F, 0x32, 350, 292, 0, 400, 160, {0, 0}, -1, 280, 0x0280, {0, 0}, 4, 6, -1, -1, -1, {0}, 0, {0, 0, 0}},
    {0x350, 0x33, 350, 334, 0, 400, 160, {0, 0}, -1, 280, 0x0280, {0, 0}, 5, 7, -1, -1, -1, {0}, 0, {0, 0, 0}},
    {0x351, 0x34, 350, 376, 0, 400, 160, {0, 0}, -1, 280, 0x0280, {0, 0}, 6, 8, -1, -1, -1, {0}, 0, {0, 0, 0}},
};

ResourceDescriptorCallbacks8 gWarpStoneUiDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    {(ResourceDescriptorCallback)WarpstoneUI_initialise, (ResourceDescriptorCallback)WarpstoneUI_release, 0x00000000,
     (ResourceDescriptorCallback)WarpstoneUI_frameStart, (ResourceDescriptorCallback)WarpstoneUI_frameEnd,
     (ResourceDescriptorCallback)WarpstoneUI_showUI, (ResourceDescriptorCallback)WarpstoneUI_setState, 0x00000000}};
