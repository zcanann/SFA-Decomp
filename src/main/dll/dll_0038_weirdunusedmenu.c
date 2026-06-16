/*
 * weirdunusedmenu (DLL 0x38) - an on-screen menu screen driven through
 * the title-menu link interface (gTitleMenuLinkInterface). Each tick,
 * WeirdUnusedMenu_run polls the interface for the current selection
 * (slot 0xC) and the pressed action (slot 0x14):
 *   - selection 1, action 0 / selection 0: leave the menu (load UI dll
 *     1, exit the cutscene, disable buttons) with a confirm sfx.
 *   - selection 1, action != 0: open the save flow - it sets a 0x1000
 *     flag on two menu widgets, plays the cancel sfx and starts the
 *     save countdown (phase lbl_803DD713 == 1, the saving phase).
 * During the save phase it calls saveGame_save once, advances a frame
 * timer (lbl_803DD712) by timeDelta, and once the timer passes the
 * phase-timer limit (lbl_803E1DF0) clears the widget flags and returns
 * to the idle phase. A scroll/offset value (lbl_803DD710) is advanced
 * each tick and clamped to 0x8C.
 * initialise loads the three menu textures and registers the widget
 * list with the interface; release frees the textures and warps home.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/debug/dimenu.h"

/* title-menu link interface vtable slot offsets (gTitleMenuLinkInterface) */
#define TITLEMENULINK_SETUP_WIDGETS 0x4
#define TITLEMENULINK_RELEASE 0x8
#define TITLEMENULINK_GET_SELECTION 0xc
#define TITLEMENULINK_GET_ACTION 0x14
#define TITLEMENULINK_SET_STATE 0x18
#define TITLEMENULINK_TOGGLE 0x2c

/* set on both menu widgets while the save dialog is up */
#define WIDGET_FLAG_SAVING 0x1000

/* sfx played on the selection==0 (cancel/back) path; no SFXqu_ name in sfx_ids.h */
#define SFX_MENU_CANCEL 0x419

typedef struct WeirdMenuWork
{
    u8 pad0[0x16 - 0x0];   /* 0x00-0x15: unknown, not touched here */
    u16 widgetFlagsA; /* 0x16: OR'd with WIDGET_FLAG_SAVING */
    u8 pad18[0x52 - 0x18]; /* 0x18-0x51: unknown, not touched here */
    u16 widgetFlagsB; /* 0x52: OR'd with WIDGET_FLAG_SAVING */
    u8 pad54[0x78 - 0x54]; /* 0x54-0x77: unknown, not touched here */
} WeirdMenuWork;

/*
 * FUN_8011daf8 / FUN_8011dafc are dimenu debug-code spillover compiled into
 * this unit (see dll_003A_dummy3a). FUN_8011dafc throttles a repeating action
 * via the signed countdown DAT_803de3a8, decremented each call by DAT_803dc070
 * (clamped to 3); on reaching zero it fires FUN_80053c98 on FUN_80006b84(1).
 * Names/types of these symbols are not established, so they stay as imported.
 */
extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();
extern void saveGame_save();

extern undefined4 DAT_803dc070;  /* per-tick countdown step (clamped to 3) */
extern undefined4 DAT_803de3a8;  /* remaining countdown ticks */

extern int* gTitleMenuLinkInterface;
extern u32 gameTextGet(int textId);

extern void loadUiDll(int id);
extern u8 framesThisStep;
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern void textureFree(u32);
/* three menu texture handles, freed in reverse load order in release */
extern u32 lbl_803DD714, lbl_803DD718, lbl_803DD71C;
extern void warpToMap(int mapId, int spawnId);
extern void cutsceneExit(void);
extern void buttonDisable(int index, int flags);
extern f32 timeDelta;
extern f32 lbl_803E1DF0;       /* save-phase timer limit */
extern s8 lbl_803DD712;        /* save-phase frame timer */
extern s16 lbl_803DD710;       /* scroll offset, clamped to 0x8C */
extern u8 lbl_803DD713;        /* phase: 0 idle, 1 saving */
extern WeirdMenuWork lbl_8031AD20;   /* widget work area */
extern u32 lbl_803DD720;       /* cached menu text handle; written at init, not read in this TU */
extern u32 lbl_8031AD98[];     /* widget layout descriptor */
extern u32 textureLoadAsset(int);

void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

undefined4
FUN_8011dafc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte countdownStep;
    undefined8 obj;

    FUN_80017a98();
    countdownStep = DAT_803dc070;
    if (3 < DAT_803dc070)
    {
        countdownStep = 3;
    }
    if ((0 < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - countdownStep, DAT_803de3a8 < 1))
    {
        obj = FUN_80006b84(1);
        FUN_80053c98(obj, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x60, 1, param_11,
                     param_12, param_13, param_14, param_15, param_16);
    }
    return 0;
}

void WeirdUnusedMenu_render(void)
{
}

void WeirdUnusedMenu_frameEnd(void)
{
}

/* scheduling/peephole off covers WeirdUnusedMenu_run and _release below */
#pragma scheduling off
#pragma peephole off
int WeirdUnusedMenu_run(void)
{
    int selection;
    int action;

    if (lbl_803DD713 == 0)
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
                lbl_803DD712 = 0;
                lbl_803DD713 = 1;
                lbl_8031AD20.widgetFlagsA =
                    (u16)(lbl_8031AD20.widgetFlagsA | WIDGET_FLAG_SAVING);
                lbl_8031AD20.widgetFlagsB =
                    (u16)(lbl_8031AD20.widgetFlagsB | WIDGET_FLAG_SAVING);
                (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_TOGGLE)))();
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
    else if (lbl_803DD713 == 1)
    {
        if ((s8)lbl_803DD712 == 0)
        {
            saveGame_save();
        }
        *(char*)&lbl_803DD712 = (int)((f32)(s8)lbl_803DD712 + timeDelta);
        if ((f32)(s8)lbl_803DD712 >= lbl_803E1DF0)
        {
            lbl_803DD713 = 0;
            lbl_8031AD20.widgetFlagsA =
                (u16)(lbl_8031AD20.widgetFlagsA & ~WIDGET_FLAG_SAVING);
            lbl_8031AD20.widgetFlagsB =
                (u16)(lbl_8031AD20.widgetFlagsB & ~WIDGET_FLAG_SAVING);
            (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_TOGGLE)))();
            (*(void (*)(int))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_SET_STATE)))(0);
        }
    }

    lbl_803DD710 = (s16)(lbl_803DD710 + (framesThisStep << 3));
    if (lbl_803DD710 > 0x8c)
    {
        lbl_803DD710 = 0x8c;
    }
    return 0;
}

void WeirdUnusedMenu_release(void)
{
    textureFree(lbl_803DD71C);
    textureFree(lbl_803DD718);
    textureFree(lbl_803DD714);
    warpToMap(0, 1);
    (*(void (*)(void))(*(int*)(*gTitleMenuLinkInterface + TITLEMENULINK_RELEASE)))();
}

/* peephole on: re-enabled for WeirdUnusedMenu_initialise (scheduling stays off) */
#pragma peephole on
void WeirdUnusedMenu_initialise(void)
{
    lbl_803DD71C = textureLoadAsset(0x31e);
    lbl_803DD718 = textureLoadAsset(0x310);
    lbl_803DD714 = textureLoadAsset(0x31f);
    lbl_803DD720 = gameTextGet(0);
    (*(void (*)(u32*, int, int, u32*, int, int, int, int, int, int, int, int))(*(int*)(*gTitleMenuLinkInterface +
        TITLEMENULINK_SETUP_WIDGETS)))(
        (u32*)&lbl_8031AD20, 2, 0, lbl_8031AD98, 0, 0, 0x5b, 0x45, 0x30, 0xff, 0xd7, 0x3d);
    lbl_803DD710 = 0;
    lbl_803DD713 = 0;
}
