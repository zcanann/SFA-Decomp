/* DLL 0x36 — enter/save name screen controller [8011B5D4-8011B868) */
#include "main/dll/dll_36.h"
#include "main/audio/sfx_ids.h"
#include "main/gameplay_runtime.h"
#include "main/pad.h"
#include "main/dll/gameplay.h"
#include "main/audio/sfx.h"
#include "sfa_light_decls.h"
extern f32 timeDelta;
extern void titleScreenPositionElements(f32 a, f32 b);
extern void fn_80135814(int p1, int p2);
extern void gameTextBoxFn_80134d40(int p1, int p2, u32 p3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int a);
extern void gameTextShowStr(void* str, int id, int x, int y);
extern float mathSinf(float x);
extern void nameEntryTextDrawFunc(void);

extern void titleScreenShowCopyright(u8 arg);
extern u16 gEnterSaveNameColorAnimTime;
extern u32 lbl_803DD6DC;
extern f32 gEnterSaveNameScrollPos;
extern u8 gEnterSaveNameLength;
extern u16 gEnterSaveNameCharTextIds[];
extern f32 lbl_803E1D80;
extern f32 lbl_803E1D84;
extern f32 lbl_803E1D88;
extern f32 lbl_803E1D8C;
extern f32 lbl_803E1D90;
extern f32 lbl_803E1D94;
extern f32 lbl_803E1D98;
extern f32 lbl_803E1D9C;

extern void set_uiDllIdx_803dc8f0(int idx);
extern void buttonDisable(int port, u32 mask);
extern void padClearAnalogInputX(int port);
extern s8 padGetStickX(int port);
extern void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv,
                                  f32* outMaxH, int glyphLang);

extern s32 gEnterSaveNameCharWidths[];
extern u8 saveFileSelect_currentSlotIndex;
extern f32 lbl_803DD6D0;
extern f32 gEnterSaveNameTargetScrollVel;
extern u8 gEnterSaveNameAutoScrolling;
extern u32 gEnterSaveNameTotalWidth;
extern u8 lbl_803DD6EC;
extern u8 lbl_803DD6ED;
extern int* gTitleMenuLinkInterface;

void EnterSaveNameScreen_render(void)
{
    extern u8 gEnterSaveNameBuffer;
    extern int gEnterSaveNameSelectedIndex;
    extern int gEnterSaveNameCharOffsets[];
    extern void* gameTextGetStr(int id);
    u8 buf[2];
    int i;

    buf[1] = 0;
    gameTextSetDrawFunc(nameEntryTextDrawFunc);
    titleScreenPositionElements(lbl_803E1D80, lbl_803E1D84);
    fn_80135814((int)(gEnterSaveNameScrollPos + lbl_803DD6DC - lbl_803E1D88), 0);
    gameTextBoxFn_80134d40(0xff, 1, 1);
    gameTextSetColor(0xc0, 0xc0, 0xc0, 0xff);
    gameTextShow(0x3ae);
    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    gameTextShow(0xed);

    for (i = 0; i < gEnterSaveNameLength; i++)
    {
        buf[0] = (&gEnterSaveNameBuffer)[i];
        gameTextShowStr(buf, i + 0x2a, 0, 0);
    }

    gEnterSaveNameColorAnimTime = gEnterSaveNameColorAnimTime + timeDelta;

    gameTextSetColor(
        (int)(mathSinf(lbl_803E1D94 * gEnterSaveNameColorAnimTime) * lbl_803E1D90 + lbl_803E1D8C),
        (int)(mathSinf(lbl_803E1D98 * gEnterSaveNameColorAnimTime) * lbl_803E1D90 + lbl_803E1D8C),
        (int)(mathSinf(lbl_803E1D9C * gEnterSaveNameColorAnimTime) * lbl_803E1D90 + lbl_803E1D8C),
        0xff);

    i = gEnterSaveNameSelectedIndex;
    gameTextShowStr(gameTextGetStr(gEnterSaveNameCharTextIds[i]), 0x56,
                    (int)((f32)(gEnterSaveNameCharOffsets[i] + 0x8a) - gEnterSaveNameScrollPos), 0);

    gameTextSetDrawFunc(NULL);
    titleScreenShowCopyright(0);
}

void EnterSaveNameScreen_frameEnd(void)
{
}

#define ENTER_SAVE_NAME_CHAR_COUNT 40
#define ENTER_SAVE_NAME_DELETE_INDEX 38
#define ENTER_SAVE_NAME_DONE_INDEX 39
#define ENTER_SAVE_NAME_MAX_LENGTH 3
#define ENTER_SAVE_NAME_MENU_DLL 5
#define ENTER_SAVE_NAME_SFX_CONFIRM 0x418
#define ENTER_SAVE_NAME_SFX_DELETE 0x419
#define ENTER_SAVE_NAME_SFX_TYPE 0x41A
#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

u32
EnterSaveNameScreen_run(u32 arg1, u32 arg2, int arg3, u32 arg4, u32 arg5
                        , u32 arg6, u32 arg7, u32 arg8)
{
    extern char gEnterSaveNameBuffer;
    extern s32 gEnterSaveNameSelectedIndex;
    extern s32 gEnterSaveNameCharOffsets[];
    extern char* gameTextGetStr(u16 textId);
    s8 stickX;
    int buttons;
    u8 moved;

    stickX = padGetStickX(0);
    padClearAnalogInputX(0);
    if (stickX != 0)
    {
        gEnterSaveNameAutoScrolling = 0;
        gEnterSaveNameTargetScrollVel = 0.08f * stickX;
        if (gEnterSaveNameTargetScrollVel * lbl_803DD6D0 < 0.0f)
        {
            gEnterSaveNameTargetScrollVel = 0.0f;
        }
    }
    else
    {
        if (gEnterSaveNameAutoScrolling != 0)
        {
            if (gEnterSaveNameSelectedIndex < 0x14)
            {
                gEnterSaveNameTargetScrollVel = -10.0f;
            }
            else
            {
                gEnterSaveNameTargetScrollVel = 10.0f;
            }
        }
        else
        {
            gEnterSaveNameTargetScrollVel = 0.0f;
        }
    }
    moved = 0;
    if (lbl_803DD6D0 < 0.0f)
    {
        gEnterSaveNameScrollPos = gEnterSaveNameScrollPos + lbl_803DD6D0;
        if (gEnterSaveNameScrollPos <= (f32)(-gEnterSaveNameCharWidths[ENTER_SAVE_NAME_DONE_INDEX] / 2))
        {
            gEnterSaveNameScrollPos = gEnterSaveNameScrollPos + gEnterSaveNameTotalWidth;
            moved = 1;
        }
        if ((0 < gEnterSaveNameSelectedIndex) &&
            (gEnterSaveNameScrollPos <= (f32)(gEnterSaveNameCharOffsets[gEnterSaveNameSelectedIndex] - gEnterSaveNameCharWidths[gEnterSaveNameSelectedIndex - 1] / 2)))
        {
            moved = 1;
        }
        if (moved != 0)
        {
            if (0.0f == gEnterSaveNameTargetScrollVel)
            {
                lbl_803DD6D0 = 0.0f;
            }
            gEnterSaveNameSelectedIndex = gEnterSaveNameSelectedIndex - 1;
            if (gEnterSaveNameSelectedIndex < 0)
            {
                gEnterSaveNameSelectedIndex = gEnterSaveNameSelectedIndex + ENTER_SAVE_NAME_CHAR_COUNT;
            }
            if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX) && (gEnterSaveNameAutoScrolling != 0))
            {
                gEnterSaveNameTargetScrollVel = 0.0f;
                lbl_803DD6D0 = 0.0f;
                gEnterSaveNameAutoScrolling = 0;
            }
        }
    }
    else if (lbl_803DD6D0 > 0.0f)
    {
        gEnterSaveNameScrollPos = gEnterSaveNameScrollPos + lbl_803DD6D0;
        if (gEnterSaveNameScrollPos >= (f32)(gEnterSaveNameTotalWidth + gEnterSaveNameCharWidths[0] / 2))
        {
            gEnterSaveNameScrollPos = gEnterSaveNameScrollPos - gEnterSaveNameTotalWidth;
            moved = 1;
        }
        if ((gEnterSaveNameSelectedIndex < ENTER_SAVE_NAME_DONE_INDEX) &&
            (gEnterSaveNameScrollPos >= (f32)(gEnterSaveNameCharOffsets[gEnterSaveNameSelectedIndex + 1] + gEnterSaveNameCharWidths[gEnterSaveNameSelectedIndex + 1] / 2)))
        {
            moved = 1;
        }
        if (moved != 0)
        {
            if (0.0f == gEnterSaveNameTargetScrollVel)
            {
                lbl_803DD6D0 = 0.0f;
            }
            gEnterSaveNameSelectedIndex = gEnterSaveNameSelectedIndex + 1;
            if (gEnterSaveNameSelectedIndex >= ENTER_SAVE_NAME_CHAR_COUNT)
            {
                gEnterSaveNameSelectedIndex = gEnterSaveNameSelectedIndex - ENTER_SAVE_NAME_CHAR_COUNT;
            }
            if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX) && (gEnterSaveNameAutoScrolling != 0))
            {
                gEnterSaveNameAutoScrolling = 0;
                gEnterSaveNameTargetScrollVel = 0.0f;
                lbl_803DD6D0 = 0.0f;
            }
        }
    }
    lbl_803DD6DC = (gEnterSaveNameScrollPos < (f32)(gEnterSaveNameTotalWidth >> 2)) ? gEnterSaveNameTotalWidth : 0;
    if ((0.0f != lbl_803DD6D0) || (0.0f != gEnterSaveNameTargetScrollVel))
    {
        if ((lbl_803DD6D0 < 0.0f) || (gEnterSaveNameTargetScrollVel < 0.0f))
        {
            if (lbl_803DD6D0 > -1.2f)
            {
                lbl_803DD6D0 = -1.2f;
            }
            else
            {
                lbl_803DD6D0 = 0.025f * (gEnterSaveNameTargetScrollVel - lbl_803DD6D0) + lbl_803DD6D0;
            }
        }
        else if (lbl_803DD6D0 < 1.2f)
        {
            lbl_803DD6D0 = 1.2f;
        }
        else
        {
            lbl_803DD6D0 = 0.025f * (gEnterSaveNameTargetScrollVel - lbl_803DD6D0) + lbl_803DD6D0;
        }
    }
    if ((stickX == 0) && (0.0f == lbl_803DD6D0))
    {
        buttons = getButtonsJustPressed(0);
        buttonDisable(0, buttons);
        if (buttons & PAD_BUTTON_A)
        {
            if ((gEnterSaveNameSelectedIndex <= 0x25) && (gEnterSaveNameLength < ENTER_SAVE_NAME_MAX_LENGTH))
            {
                (&gEnterSaveNameBuffer)[gEnterSaveNameLength++] = *gameTextGetStr(gEnterSaveNameCharTextIds[gEnterSaveNameSelectedIndex]);
                (&gEnterSaveNameBuffer)[*(volatile u8*)&gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
                Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_TYPE);
                if (gEnterSaveNameLength == ENTER_SAVE_NAME_MAX_LENGTH)
                {
                    gEnterSaveNameAutoScrolling = 1;
                }
            }
            else if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DELETE_INDEX) && (gEnterSaveNameLength != 0))
            {
                Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
                gEnterSaveNameLength -= 1;
                (&gEnterSaveNameBuffer)[gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
                gEnterSaveNameAutoScrolling = 0;
            }
            else if (gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX)
            {
                if (gEnterSaveNameLength == 0)
                {
                    gEnterSaveNameBuffer = 'F';
                    (&gEnterSaveNameBuffer)[1] = 'O';
                    (&gEnterSaveNameBuffer)[2] = 'X';
                    (&gEnterSaveNameBuffer)[3] = 0;
                }
                Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_CONFIRM);
                gplayNewGame(&gEnterSaveNameBuffer, saveFileSelect_currentSlotIndex);
                loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
                lbl_803DD6EC = 2;
            }
        }
        else if (buttons & PAD_BUTTON_B)
        {
            gEnterSaveNameAutoScrolling = 0;
            Sfx_PlayFromObject(0,ENTER_SAVE_NAME_SFX_DELETE);
            if (gEnterSaveNameLength != 0)
            {
                gEnterSaveNameLength -= 1;
                (&gEnterSaveNameBuffer)[gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
            }
            else
            {
                loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
                set_uiDllIdx_803dc8f0(ENTER_SAVE_NAME_MENU_DLL);
            }
        }
    }
    return 0;
}

void EnterSaveNameScreen_release(void)
{
    ((void (*)(void))((void**)*gTitleMenuLinkInterface)[2])();
}

void EnterSaveNameScreen_initialise(void)
{
    extern char gEnterSaveNameBuffer;
    extern s32 gEnterSaveNameSelectedIndex;
    extern s32 gEnterSaveNameCharOffsets[];
    extern char* gameTextGetStr(u16 textId);
    int i;
    f32 width;

    lbl_803DD6EC = 2;
    lbl_803DD6ED = 2;
    gEnterSaveNameLength = 0;
    gEnterSaveNameBuffer = 0;
    gEnterSaveNameTotalWidth = 0;

    for (i = 0; i < ENTER_SAVE_NAME_CHAR_COUNT; i++)
    {
        gameTextMeasureString((u8*)gameTextGetStr(gEnterSaveNameCharTextIds[i]), 1.0f, &width, NULL,
                              NULL, NULL, -1);
        gEnterSaveNameCharWidths[i] = width;
        gEnterSaveNameCharOffsets[i] = gEnterSaveNameTotalWidth;
        gEnterSaveNameTotalWidth += gEnterSaveNameCharWidths[i];
    }

    gEnterSaveNameSelectedIndex = 0;
    gEnterSaveNameScrollPos = (f32)(gEnterSaveNameCharWidths[0] / 2);
    lbl_803DD6DC = gEnterSaveNameTotalWidth;
    gEnterSaveNameAutoScrolling = 0;
    Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_CONFIRM);
}
