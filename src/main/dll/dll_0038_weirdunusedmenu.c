/*
 * weirdunusedmenu (DLL 0x38) - an on-screen menu screen driven through
 * the title-menu link interface (gTitleMenuLinkInterface). Each tick,
 * WeirdUnusedMenu_run polls the interface for the current selection
 * (slot 0xC) and the pressed action (slot 0x14):
 *   - selection 1, action 0: leave the menu (load UI dll 1, exit the
 *     cutscene, disable buttons) with a confirm sfx.
 *   - selection 0: leave the menu the same way, but with the cancel sfx
 *     (SFX_MENU_CANCEL).
 *   - selection 1, action != 0: open the save flow - it sets a 0x1000
 *     flag on two menu widgets, plays the save/confirm sfx
 *     (SFXqu_shortsob1) and starts the save countdown (phase
 *     gWeirdMenuPhase == 1, the saving phase).
 * During the save phase it calls saveGame_save once, advances a frame
 * timer (gWeirdMenuSaveTimer) by timeDelta, and once the timer passes the
 * phase-timer limit (gWeirdMenuSaveTimerLimit) clears the widget flags and returns
 * to the idle phase. A scroll/offset value (gWeirdMenuScrollOffset) is advanced
 * each tick and clamped to 0x8C.
 * initialise loads the three menu textures and registers the widget
 * list with the interface; release frees the textures and warps home.
 */
#include "main/audio/sfx_ids.h"
#include "ghidra_import.h"
#include "main/sfa_extern_decls.h"
#include "main/audio/sfx.h"

/* title-menu link interface vtable slot offsets (gTitleMenuLinkInterface) */
#define TITLEMENULINK_SETUP_WIDGETS 0x4
#define TITLEMENULINK_RELEASE 0x8
#define TITLEMENULINK_GET_SELECTION 0xc
#define TITLEMENULINK_GET_ACTION 0x14
#define TITLEMENULINK_SET_STATE 0x18
#define TITLEMENULINK_TOGGLE 0x2c

/* set on both menu widgets while the save dialog is up */
#define WIDGET_FLAG_SAVING 0x1000

/* sfx played on the selection==0 (cancel/back) path; 0x419 has no named entry in sfx_ids.h */
#define SFX_MENU_CANCEL 0x419

typedef struct WeirdMenuWork
{
    u8 pad0[0x16 - 0x0];   /* 0x00-0x15: unknown, not touched here */
    u16 widgetFlagsA; /* 0x16: OR'd with WIDGET_FLAG_SAVING */
    u8 pad18[0x52 - 0x18]; /* 0x18-0x51: unknown, not touched here */
    u16 widgetFlagsB; /* 0x52: OR'd with WIDGET_FLAG_SAVING */
    u8 pad54[0x78 - 0x54]; /* 0x54-0x77: unknown, not touched here */
} WeirdMenuWork;

extern void saveGame_save();
extern int* gTitleMenuLinkInterface;
extern u32 gameTextGet(int textId);
extern void loadUiDll(int index);
extern u8 framesThisStep;

extern void textureFree(u32);
extern u32 gWeirdMenuTextureC, gWeirdMenuTextureB, gWeirdMenuTextureA;
extern void warpToMap(int idx, s8 transType);

extern void buttonDisable(int port, u32 mask);
extern f32 timeDelta;
extern f32 gWeirdMenuSaveTimerLimit;       /* save-phase timer limit */
extern s8 gWeirdMenuSaveTimer;        /* save-phase frame timer */
extern s16 gWeirdMenuScrollOffset;       /* scroll offset, clamped to 0x8C */
extern u8 gWeirdMenuPhase;        /* phase: 0 idle, 1 saving */
extern WeirdMenuWork gWeirdMenuWidgetWork;   /* widget work area */
extern u32 gWeirdMenuTextHandle;       /* cached menu text handle; written at init, not read in this TU */
extern u32 gWeirdMenuWidgetLayout[];     /* widget layout descriptor */
extern u32 textureLoadAsset(int);

void WeirdUnusedMenu_render(void)
{
}

void WeirdUnusedMenu_frameEnd(void)
{
}

#pragma scheduling off
#pragma peephole off
int WeirdUnusedMenu_run(void)
{
    int selection;
    int action;

    if (gWeirdMenuPhase == 0)
    {
        selection = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_GET_SELECTION)))();
        action = (*(int (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_GET_ACTION)))();
        if (selection == 1)
        {
            if (action == 0)
            {
                Sfx_PlayFromObject(0, SFXqu_longsob2);
                loadUiDll(1);
                cutsceneExit();
                buttonDisable(0, 0x300);
            }
            else
            {
                Sfx_PlayFromObject(0, SFXqu_shortsob1);
                gWeirdMenuSaveTimer = 0;
                gWeirdMenuPhase = 1;
                gWeirdMenuWidgetWork.widgetFlagsA =
                    (u16)(gWeirdMenuWidgetWork.widgetFlagsA | WIDGET_FLAG_SAVING);
                gWeirdMenuWidgetWork.widgetFlagsB =
                    (u16)(gWeirdMenuWidgetWork.widgetFlagsB | WIDGET_FLAG_SAVING);
                (*(void (*)(u32*))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_TOGGLE)))(
                    (u32*)&gWeirdMenuWidgetWork);
            }
        }
        else if (selection == 0)
        {
            Sfx_PlayFromObject(0, SFX_MENU_CANCEL);
            loadUiDll(1);
            cutsceneExit();
            buttonDisable(0, 0x300);
        }
    }
    else if (gWeirdMenuPhase == 1)
    {
        if ((s8)gWeirdMenuSaveTimer == 0)
        {
            saveGame_save();
        }
        if ((f32)(s8)(gWeirdMenuSaveTimer = ((f32)(s8)gWeirdMenuSaveTimer + timeDelta)) >= gWeirdMenuSaveTimerLimit)
        {
            gWeirdMenuPhase = 0;
            gWeirdMenuWidgetWork.widgetFlagsA =
                (u16)(gWeirdMenuWidgetWork.widgetFlagsA & ~WIDGET_FLAG_SAVING);
            gWeirdMenuWidgetWork.widgetFlagsB =
                (u16)(gWeirdMenuWidgetWork.widgetFlagsB & ~WIDGET_FLAG_SAVING);
            (*(void (*)(u32*))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_TOGGLE)))(
                (u32*)&gWeirdMenuWidgetWork);
            (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_SET_STATE)))(0);
        }
    }

    gWeirdMenuScrollOffset = (s16)(gWeirdMenuScrollOffset + (framesThisStep << 3));
    if (gWeirdMenuScrollOffset > 0x8c)
    {
        gWeirdMenuScrollOffset = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void)
{
    textureFree(gWeirdMenuTextureA);
    textureFree(gWeirdMenuTextureB);
    textureFree(gWeirdMenuTextureC);
    warpToMap(0, 1);
    (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_RELEASE)))();
}

#pragma peephole on
void WeirdUnusedMenu_initialise(void)
{
    gWeirdMenuTextureA = textureLoadAsset(0x31e);
    gWeirdMenuTextureB = textureLoadAsset(0x310);
    gWeirdMenuTextureC = textureLoadAsset(0x31f);
    gWeirdMenuTextHandle = gameTextGet(0);
    (*(void (*)(u32*, int, int, u32*, int, int, int, int, int, int, int, int))(*(int*)(*gTitleMenuLinkInterface +
        TITLEMENULINK_SETUP_WIDGETS)))(
        (u32*)&gWeirdMenuWidgetWork, 2, 0, gWeirdMenuWidgetLayout, 0, 0, 0x5b, 0x45, 0x30, 0xff, 0xd7, 0x3d);
    gWeirdMenuScrollOffset = 0;
    gWeirdMenuPhase = 0;
}
