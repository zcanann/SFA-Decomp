#include "main/pad.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/textrender_api.h"
#include "dlls/object_descriptor.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_003C_link.h"
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/gametext_color_api.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/front_game_text_box_api.h"
#include "main/dll/savegame.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/model_engine.h"
#include "main/dll/dll_36.h"

extern u16 gEnterSaveNameCharTextIds[];

s32 gEnterSaveNameCharWidths[40];
s32 gEnterSaveNameCharOffsets[40];
u8 gEnterSaveNameLength;
char gEnterSaveNameBuffer[4];
u8 lbl_803DD6ED;
u8 lbl_803DD6EC;
u32 gEnterSaveNameTotalWidth;
s32 gEnterSaveNameSelectedIndex;
f32 gEnterSaveNameScrollPos;
u32 gEnterSaveNameScrollWrapOffset;
u8 gEnterSaveNameAutoScrolling;
u16 gEnterSaveNameColorAnimTime;
f32 gEnterSaveNameTargetScrollVel;
f32 gEnterSaveNameScrollVelocity;


void EnterSaveNameScreen_render(void)
{
    u8 buf[2];
    int i;

    buf[1] = 0;
    gameTextSetDrawFunc(nameEntryTextDrawFunc);
    titleScreenPositionElements(40.0f, 120.0f);
    nameEntrySetScroll((int)(gEnterSaveNameScrollPos + gEnterSaveNameScrollWrapOffset - 8.0f), 0);
    titleScreenDrawMenuFrame(0xff, 1, 1);
    gameTextSetColor(0xc0, 0xc0, 0xc0, 0xff);
    gameTextShow(0x3ae);
    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    gameTextSetDrawFunc(titleScreenTextDrawFunc);
    gameTextShow(0xed);

    for (i = 0; i < gEnterSaveNameLength; i++)
    {
        buf[0] = gEnterSaveNameBuffer[i];
        gameTextShowStr((char*)buf, i + 0x2a, 0, 0);
    }

    gEnterSaveNameColorAnimTime += timeDelta;

    gameTextSetColor((int)(mathSinf(0.17259522f * gEnterSaveNameColorAnimTime) * 128.0f + 127.0f),
                        (int)(mathSinf(0.14382935f * gEnterSaveNameColorAnimTime) * 128.0f + 127.0f),
                        (int)(mathSinf(0.11506347f * gEnterSaveNameColorAnimTime) * 128.0f + 127.0f),
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

#define ENTER_SAVE_NAME_CHAR_COUNT   40
#define ENTER_SAVE_NAME_DELETE_INDEX 38
#define ENTER_SAVE_NAME_DONE_INDEX   39
#define ENTER_SAVE_NAME_MAX_LENGTH   3
#define ENTER_SAVE_NAME_MENU_DLL     5
#define ENTER_SAVE_NAME_SFX_CONFIRM  0x418
#define ENTER_SAVE_NAME_SFX_DELETE   0x419
#define ENTER_SAVE_NAME_SFX_TYPE     0x41A

u32 EnterSaveNameScreen_run(void)
{
    s8 stickX;
    int buttons;
    u8 moved;
    u8 slotIndex;
    char* selectedText;

    stickX = padGetStickX(0);
    padClearAnalogInputX(0);
    if (stickX != 0)
    {
        gEnterSaveNameAutoScrolling = 0;
        gEnterSaveNameTargetScrollVel = 0.08f * stickX;
        if (gEnterSaveNameTargetScrollVel * gEnterSaveNameScrollVelocity < 0.0f)
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
    if (gEnterSaveNameScrollVelocity < 0.0f)
    {
        gEnterSaveNameScrollPos += gEnterSaveNameScrollVelocity;
        if (gEnterSaveNameScrollPos <= (f32)(-gEnterSaveNameCharWidths[ENTER_SAVE_NAME_DONE_INDEX] / 2))
        {
            gEnterSaveNameScrollPos += gEnterSaveNameTotalWidth;
            moved = 1;
        }
        if ((gEnterSaveNameSelectedIndex > 0) &&
            (gEnterSaveNameScrollPos <= (f32)(gEnterSaveNameCharOffsets[gEnterSaveNameSelectedIndex] -
                                              gEnterSaveNameCharWidths[gEnterSaveNameSelectedIndex - 1] / 2)))
        {
            moved = 1;
        }
        if (moved != 0)
        {
            if (gEnterSaveNameTargetScrollVel == 0.0f)
            {
                gEnterSaveNameScrollVelocity = 0.0f;
            }
            gEnterSaveNameSelectedIndex -= 1;
            if (gEnterSaveNameSelectedIndex < 0)
            {
                gEnterSaveNameSelectedIndex += ENTER_SAVE_NAME_CHAR_COUNT;
            }
            if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX) && (gEnterSaveNameAutoScrolling != 0))
            {
                gEnterSaveNameTargetScrollVel = 0.0f;
                gEnterSaveNameScrollVelocity = 0.0f;
                gEnterSaveNameAutoScrolling = 0;
            }
        }
    }
    else if (gEnterSaveNameScrollVelocity > 0.0f)
    {
        gEnterSaveNameScrollPos += gEnterSaveNameScrollVelocity;
        if (gEnterSaveNameScrollPos >= (f32)(gEnterSaveNameTotalWidth + gEnterSaveNameCharWidths[0] / 2))
        {
            gEnterSaveNameScrollPos -= gEnterSaveNameTotalWidth;
            moved = 1;
        }
        if ((gEnterSaveNameSelectedIndex < ENTER_SAVE_NAME_DONE_INDEX) &&
            (gEnterSaveNameScrollPos >= (f32)(gEnterSaveNameCharOffsets[gEnterSaveNameSelectedIndex + 1] +
                                              gEnterSaveNameCharWidths[gEnterSaveNameSelectedIndex + 1] / 2)))
        {
            moved = 1;
        }
        if (moved != 0)
        {
            if (gEnterSaveNameTargetScrollVel == 0.0f)
            {
                gEnterSaveNameScrollVelocity = 0.0f;
            }
            gEnterSaveNameSelectedIndex += 1;
            if (gEnterSaveNameSelectedIndex >= ENTER_SAVE_NAME_CHAR_COUNT)
            {
                gEnterSaveNameSelectedIndex -= ENTER_SAVE_NAME_CHAR_COUNT;
            }
            if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX) && (gEnterSaveNameAutoScrolling != 0))
            {
                gEnterSaveNameAutoScrolling = 0;
                gEnterSaveNameTargetScrollVel = 0.0f;
                gEnterSaveNameScrollVelocity = 0.0f;
            }
        }
    }
    gEnterSaveNameScrollWrapOffset = (gEnterSaveNameScrollPos < (f32)(gEnterSaveNameTotalWidth >> 2)) ? gEnterSaveNameTotalWidth : 0;
    if ((gEnterSaveNameScrollVelocity != 0.0f) || (gEnterSaveNameTargetScrollVel != 0.0f))
    {
        if ((gEnterSaveNameScrollVelocity < 0.0f) || (gEnterSaveNameTargetScrollVel < 0.0f))
        {
            if (gEnterSaveNameScrollVelocity > -1.2f)
            {
                gEnterSaveNameScrollVelocity = -1.2f;
            }
            else
            {
                gEnterSaveNameScrollVelocity = 0.025f * (gEnterSaveNameTargetScrollVel - gEnterSaveNameScrollVelocity) + gEnterSaveNameScrollVelocity;
            }
        }
        else if (gEnterSaveNameScrollVelocity < 1.2f)
        {
            gEnterSaveNameScrollVelocity = 1.2f;
        }
        else
        {
            gEnterSaveNameScrollVelocity = 0.025f * (gEnterSaveNameTargetScrollVel - gEnterSaveNameScrollVelocity) + gEnterSaveNameScrollVelocity;
        }
    }
    if ((stickX == 0) && (gEnterSaveNameScrollVelocity == 0.0f))
    {
        buttons = getButtonsJustPressed(0);
        buttonDisable(0, buttons);
        if (buttons & PAD_BUTTON_A)
        {
            if ((gEnterSaveNameSelectedIndex <= 0x25) && (gEnterSaveNameLength < ENTER_SAVE_NAME_MAX_LENGTH))
            {
                selectedText = gameTextGetStr(gEnterSaveNameCharTextIds[gEnterSaveNameSelectedIndex]);
                gEnterSaveNameBuffer[gEnterSaveNameLength++] = selectedText[0];
                gEnterSaveNameBuffer[gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
                Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_TYPE);
                if (gEnterSaveNameLength == ENTER_SAVE_NAME_MAX_LENGTH)
                {
                    gEnterSaveNameAutoScrolling = 1;
                }
            }
            else if ((gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DELETE_INDEX) && (gEnterSaveNameLength != 0))
            {
                Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_DELETE);
                gEnterSaveNameLength -= 1;
                gEnterSaveNameBuffer[gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
                gEnterSaveNameAutoScrolling = 0;
            }
            else if (gEnterSaveNameSelectedIndex == ENTER_SAVE_NAME_DONE_INDEX)
            {
                if (gEnterSaveNameLength == 0)
                {
                    gEnterSaveNameBuffer[0] = 'F';
                    gEnterSaveNameBuffer[1] = 'O';
                    gEnterSaveNameBuffer[2] = 'X';
                    gEnterSaveNameBuffer[3] = 0;
                }
                Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_CONFIRM);
                slotIndex = saveFileSelect_currentSlotIndex;
                gplayNewGame(gEnterSaveNameBuffer, slotIndex);
                loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
                lbl_803DD6EC = 2;
            }
        }
        else if (buttons & PAD_BUTTON_B)
        {
            gEnterSaveNameAutoScrolling = 0;
            Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_DELETE);
            if (gEnterSaveNameLength != 0)
            {
                gEnterSaveNameLength -= 1;
                gEnterSaveNameBuffer[gEnterSaveNameLength] = 0;
                lbl_803DD6EC = 2;
            }
            else
            {
                loadUiDll(ENTER_SAVE_NAME_MENU_DLL);
                setCurUiDll(ENTER_SAVE_NAME_MENU_DLL);
            }
        }
    }
    return 0;
}

void EnterSaveNameScreen_release(void)
{
    gTitleMenuLinkInterface->vtable->free();
}

void EnterSaveNameScreen_initialise(void)
{
    int i;
    f32 width;

    lbl_803DD6EC = 2;
    lbl_803DD6ED = 2;
    gEnterSaveNameLength = 0;
    gEnterSaveNameBuffer[0] = 0;
    gEnterSaveNameTotalWidth = 0;

    for (i = 0; i < ENTER_SAVE_NAME_CHAR_COUNT; i++)
    {
        gameTextMeasureString((u8*)gameTextGetStr(gEnterSaveNameCharTextIds[i]), 1.0f, &width, NULL, NULL, NULL, -1);
        gEnterSaveNameCharWidths[i] = width;
        gEnterSaveNameCharOffsets[i] = gEnterSaveNameTotalWidth;
        gEnterSaveNameTotalWidth += gEnterSaveNameCharWidths[i];
    }

    gEnterSaveNameSelectedIndex = 0;
    gEnterSaveNameScrollPos = (f32)(gEnterSaveNameCharWidths[0] / 2);
    gEnterSaveNameScrollWrapOffset = gEnterSaveNameTotalWidth;
    gEnterSaveNameAutoScrolling = 0;
    Sfx_PlayFromObject(0, ENTER_SAVE_NAME_SFX_CONFIRM);
}

u16 gEnterSaveNameCharTextIds[40] = {0x037f, 0x0380, 0x0381, 0x0382, 0x0383, 0x0384, 0x0385, 0x0386, 0x0387, 0x0388,
                                     0x0389, 0x038a, 0x038b, 0x038c, 0x038d, 0x038e, 0x038f, 0x0390, 0x0391, 0x0392,
                                     0x0393, 0x0394, 0x0395, 0x0396, 0x0397, 0x0398, 0x0489, 0x048a, 0x048b, 0x048c,
                                     0x048d, 0x048e, 0x048f, 0x0490, 0x0491, 0x0492, 0x0399, 0x039a, 0x039b, 0x039c};

ObjectDescriptor6 EnterSaveNameScreen_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)EnterSaveNameScreen_initialise,
    (ObjectDescriptorCallback)EnterSaveNameScreen_release,
    NULL,
    (ObjectDescriptorCallback)EnterSaveNameScreen_run,
    (ObjectDescriptorCallback)EnterSaveNameScreen_frameEnd,
    (ObjectDescriptorCallback)EnterSaveNameScreen_render,
};
