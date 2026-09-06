#include "dlls/object_descriptor.h"
#include "main/texture.h"
#include "main/rcp_dolphin_api.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/textrender_api.h"
#include "main/dll/dll_0038_weirdunusedmenu.h"
#include "main/dll/dll_003C_link.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/savegame.h"
#include "main/model_engine.h"
#include "main/pad_api.h"

#define WIDGET_FLAG_SAVING 0x1000

#define WEIRDMENU_TEXTURE_A_ID 0x31e
#define WEIRDMENU_TEXTURE_B_ID 0x310
#define WEIRDMENU_TEXTURE_C_ID 0x31f

#define SFX_MENU_CANCEL 0x419

#define PAD_CONFIRM_MASK (PAD_BUTTON_A | PAD_BUTTON_B)


void* gWeirdMenuTextHandle[2];
Texture* gWeirdMenuTextureA;
Texture* gWeirdMenuTextureB;
Texture* gWeirdMenuTextureC;
u8 gWeirdMenuPhase;
s8 gWeirdMenuSaveTimer;
s16 gWeirdMenuScrollOffset;

TitleMenuTextEntry gWeirdMenuWidgetWork[2] = {
    {
        0x0000,
        0x00A1,
        86,
        0,
        161,
        86,
        -1,
        {0, 0},
        0,
        0x0380,
        0x0000,
        {0x00, 0xFF},
        1,
        -1,
        -1,
        -1,
        0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
    {
        0x0001,
        0x00A1,
        109,
        0,
        161,
        86,
        -1,
        {0, 0},
        0,
        0x0380,
        0x0000,
        {0x00, 0x00},
        -1,
        -1,
        -1,
        -1,
        0,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,
        {0, 0, 0},
    },
};

u32 gWeirdMenuWidgetLayout[3] = {0x000000f9, 0xffffffff, 0x00000102};
typedef struct WeirdUnusedMenuDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback run;
    ObjectDescriptorCallback frameEnd;
    ObjectDescriptorCallback render;
    ObjectDescriptorCallback slot06;
} WeirdUnusedMenuDllInterface;

WeirdUnusedMenuDllInterface WeirdUnusedMenu_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)WeirdUnusedMenu_initialise,
    (ObjectDescriptorCallback)WeirdUnusedMenu_release,
    0,
    (ObjectDescriptorCallback)WeirdUnusedMenu_run,
    (ObjectDescriptorCallback)WeirdUnusedMenu_frameEnd,
    (ObjectDescriptorCallback)WeirdUnusedMenu_render,
    0,
};

void WeirdUnusedMenu_render(void)
{
}

void WeirdUnusedMenu_frameEnd(void)
{
}

int WeirdUnusedMenu_run(void)
{
    int selection;
    int action;

    if (gWeirdMenuPhase == 0)
    {
        action = gTitleMenuLinkInterface->vtable->update();
        selection = gTitleMenuLinkInterface->vtable->getSelected();
        if (action == 1)
        {
            if (selection == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_103);
                loadUiDll(1);
                cutsceneExit();
                buttonDisable(0, PAD_CONFIRM_MASK);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_104);
                gWeirdMenuSaveTimer = 0;
                gWeirdMenuPhase = 1;
                gWeirdMenuWidgetWork[0].flags = (u16)(gWeirdMenuWidgetWork[0].flags | WIDGET_FLAG_SAVING);
                gWeirdMenuWidgetWork[1].flags = (u16)(gWeirdMenuWidgetWork[1].flags | WIDGET_FLAG_SAVING);
                gTitleMenuLinkInterface->vtable->copyItems(gWeirdMenuWidgetWork);
            }
        }
        else if (action == 0)
        {
            Sfx_PlayFromObject(0, SFX_MENU_CANCEL);
            loadUiDll(1);
            cutsceneExit();
            buttonDisable(0, PAD_CONFIRM_MASK);
        }
    }
    else if (gWeirdMenuPhase == 1)
    {
        if (gWeirdMenuSaveTimer == 0)
        {
            saveGame_save();
        }
        if ((f32)(gWeirdMenuSaveTimer = ((f32)gWeirdMenuSaveTimer + timeDelta)) >= 120.0f)
        {
            gWeirdMenuPhase = 0;
            gWeirdMenuWidgetWork[0].flags = (u16)(gWeirdMenuWidgetWork[0].flags & ~WIDGET_FLAG_SAVING);
            gWeirdMenuWidgetWork[1].flags = (u16)(gWeirdMenuWidgetWork[1].flags & ~WIDGET_FLAG_SAVING);
            gTitleMenuLinkInterface->vtable->copyItems(gWeirdMenuWidgetWork);
            gTitleMenuLinkInterface->vtable->setSelected(0);
        }
    }

    gWeirdMenuScrollOffset += (framesThisStep << 3);
    if (gWeirdMenuScrollOffset > 0x8c)
    {
        gWeirdMenuScrollOffset = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void)
{
    textureFree((Texture*)((u8*)gWeirdMenuTextureA));
    textureFree((Texture*)((u8*)gWeirdMenuTextureB));
    textureFree((Texture*)((u8*)gWeirdMenuTextureC));
    warpToMap(0, 1);
    gTitleMenuLinkInterface->vtable->free();
}

void WeirdUnusedMenu_initialise(void)
{
    gWeirdMenuTextureA = textureLoadAsset(WEIRDMENU_TEXTURE_A_ID);
    gWeirdMenuTextureB = textureLoadAsset(WEIRDMENU_TEXTURE_B_ID);
    gWeirdMenuTextureC = textureLoadAsset(WEIRDMENU_TEXTURE_C_ID);
    gWeirdMenuTextHandle[0] = gameTextGet(0);
    gTitleMenuLinkInterface->vtable->setup(gWeirdMenuWidgetWork, 2, 0, gWeirdMenuWidgetLayout, 0, 0, 0x5b, 0x45,
                                          0x30, 0xff, 0xd7, 0x3d);
    gWeirdMenuScrollOffset = 0;
    gWeirdMenuPhase = 0;
}
