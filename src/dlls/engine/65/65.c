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
#include "main/dll/dll_0041_warpstoneui.h"
#include "main/resource.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_003C_link.h"

int gWarpStoneUiTextPosY = 0x140;
int gWarpStoneUiTextureX = 0x136;
int gWarpStoneUiTextureY = 0x10E;
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
extern WarpstoneMenuItem gWarpStoneUiMenuItemTemplates[];

WarpstoneMenuItem gWarpStoneUiMenuItems[WARPSTONE_UI_ENTRY_COUNT];
WarpstoneEntry gWarpStoneUiEntryTable[WARPSTONE_UI_ENTRY_COUNT] = {
    {0x0ABA, 1, 0}, {0x0ABD, 4, 0}, {0x0ABE, 5, 0}, {0x0ABF, 6, 0}, {0x0AC0, 7, 0}, {0x0AC1, 8, 0},
};
int gWarpStoneUiSelectedIndices[0x6];

static int WarpstoneUI_getMenuItems(const WarpstoneMenuItem* templates, WarpstoneMenuItem* items,
                                    const WarpstoneEntry* entries, int count, int* selectedIndices) {
    int yStart;
    WarpstoneMenuItem* lastDst;
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
            memcpy(&items[slot], &templates[entry], sizeof(WarpstoneMenuItem));
            lastDst = &items[slot];
            items[slot].y = yStart + slot * 0x2a;
            items[slot].previousItem = slot - 1;
            items[slot].nextItem = slot + 1;
            *selectedIndices++ = entry;
            slot++;
        }
    }
    if (lastDst != NULL) {
        lastDst->nextItem = -1;
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
                WarpstoneUI_getMenuItems(gWarpStoneUiMenuItemTemplates, gWarpStoneUiMenuItems,
                                         gWarpStoneUiEntryTable, WARPSTONE_UI_ENTRY_COUNT, gWarpStoneUiSelectedIndices);
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

WarpstoneMenuItem gWarpStoneUiMenuItemTemplates[6] = {
    {0x34C, 0x2F, 350, 82,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0x34, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     -1, 1,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {0x34D, 0x30, 350, 208,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0xA0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     2, 4,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {0x429, 0x31, 350, 250,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0xA0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     3, 5,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {0x34F, 0x32, 350, 292,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0xA0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     4, 6,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {0x350, 0x33, 350, 334,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0xA0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     5, 7,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {0x351, 0x34, 350, 376,
     {0x00, 0x00, 0x01, 0x90, 0x00, 0xA0, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x02, 0x80, 0x00, 0x00},
     6, 8,
     {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
};

ResourceDescriptorCallbacks8 gWarpStoneUiDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    {(ResourceDescriptorCallback)WarpstoneUI_initialise, (ResourceDescriptorCallback)WarpstoneUI_release, 0x00000000,
     (ResourceDescriptorCallback)WarpstoneUI_frameStart, (ResourceDescriptorCallback)WarpstoneUI_frameEnd,
     (ResourceDescriptorCallback)WarpstoneUI_showUI, (ResourceDescriptorCallback)WarpstoneUI_setState, 0x00000000}};
