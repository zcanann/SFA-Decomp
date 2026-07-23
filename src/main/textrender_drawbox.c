#include "ghidra_import.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/hud_visibility_api.h"
#include "main/audio/sfx.h"
#include "main/gametext_api.h"
#define GAMETEXT_COLOR_U8
#include "main/gametext_color_api.h"
#include "main/gameloop_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_shared_internal.h"
#include "main/gametext_task_api.h"
#include "main/gx_scissor_api.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSFont.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/savedata_struct.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "main/lightmap_text_color_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "track/intersect_api.h"
#include "string.h"
#include "main/lightmap.h"

extern GXColor gGameTextBoxFillColor;

void boxDrawFn_8001c5ac(u16* strPtr, int boxId, u8* box);

void subtitleStart(int x)
{
    if (gSubtitlesEnabled != 0)
    {
        gGameTextPendingTextId = x;
        gGameTextPendingDir = getCurGameText();
        gGameTextSequenceMode = 0;
        gGameTextSavedDir = -1;
        gSubtitleActive = 1;
        gSubtitleColorR = 0xff;
        gSubtitleColorG = 0xff;
        gSubtitleColorB = 0xff;
        gSubtitleColorA = 0xff;
    }
}

static inline int gameTextIsTaskTextAllowed(int taskId)
{
    s16* taskList;
    int count;

    taskList = gGameTextTaskTextAllowList;
    for (count = 0; count < 0xb; count++)
    {
        if (taskId == taskList[count])
        {
            return 1;
        }
    }
    return 0;
}

void gameTextLoadTaskText(int taskId)
{
    int textId;
    int dirId;

    if (gameTextGetTaskText(taskId, &textId, &dirId) != 0)
    {
        if (gSubtitlesEnabled == 0)
        {
            if (gameTextIsTaskTextAllowed(taskId) == 0)
            {
                return;
            }
        }

        gGameTextPendingTextId = textId;
        gGameTextPendingDir = (void*)dirId;
        if (dirId == 0x29)
        {
            loadGameTextSequence(dirId, textId);
            gGameTextSequenceMode = 1;
        }
        else
        {
            gGameTextSavedDir = (int)getCurGameText();
            gameTextLoadDir((int)gGameTextPendingDir);
            gGameTextSequenceMode = 0;
        }
        gSubtitleActive = 1;
        gSubtitleColorR = 0xff;
        gSubtitleColorG = 0xff;
        gSubtitleColorB = 0xff;
        gSubtitleColorA = 0xff;
    }
}

int subtitleIsActive(void)
{
    int ret;

    ret = 0;
    if (gSubtitlesEnabled != 0)
    {
        if (gSubtitleActive != 0)
        {
            ret = 1;
        }
    }
    return ret;
}

int setSubtitlesEnabled(int enabled)
{
    int old = gSubtitlesEnabled;
    gSubtitlesEnabled = enabled;
    if (enabled == 0)
    {
        subtitleFn_8001b700();
    }
    return old;
}

void gameTextInitFn_8001bd14(void)
{
    int i;
    int zero;
    int (*scratch)[8];

    zero = 0;
    gSubtitleActive = zero;
    gSubtitlesEnabled = 1;
    gGameTextSavedDir = -1;

    scratch = (int (*)[8])gSubtitleLineTable;
    for (i = 0; i < 32; i++)
    {
        scratch[i][0] = zero;
        scratch[i][1] = zero;
        scratch[i][2] = zero;
        scratch[i][3] = zero;
        scratch[i][4] = zero;
        scratch[i][5] = zero;
        scratch[i][6] = zero;
        scratch[i][7] = zero;
    }
}

void subtitleFreeBoxTextures(int mode)
{
    switch (mode)
    {
    case 3:
        textureFree(gSubtitleBoxTextures[0]);
        textureFree(gSubtitleBoxTextures[1]);
        textureFree(gSubtitleBoxTextures[2]);
        break;
    }
}

void subtitleLoadBoxTextures(int mode)
{
    switch (mode)
    {
    case 3:
        gSubtitleBoxTextures[0] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_LEFT);
        gSubtitleBoxTextures[1] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_MID);
        gSubtitleBoxTextures[2] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_RIGHT);
        break;
    }
}

void gameTextDrawBox(struct GameTextDef* strPtr, int boxId, GameTextBox* box)
{
    int c6y1;
    int c6y0;
    int c6x1;
    int c6x0;
    int c3y1;
    int c3y0;
    int c3x1;
    s16 savedY;
    s16 savedX;
    u16 boxFlags;
    u8* cur;
    int cy;
    int cx;
    int hh;
    int hw;
    s16 x7;
    s16 y7;
    u16 w7;
    u16 h7;
    int c3x0;
    int y2;
    int w2;
    int xw;
    s16 x2;
    int half;
    int rem;

    savedX = ((GameTextBox*)box)->cursorX;
    savedY = ((GameTextBox*)box)->cursorY;
    boxFlags = ((GameTextBox*)box)->flags;
    if (boxFlags & 1)
    {
        return;
    }
    ((GameTextBox*)box)->flags = boxFlags | 1;
    switch (((GameTextBox*)box)->style)
    {
    case 5:
        return;
    case 7:
        if ((int)getCurGameText() == 3)
        {
            u16 bh = ((GameTextBox*)box)->height;
            u16 bw = ((GameTextBox*)box)->width;
            s16 by = ((GameTextBox*)box)->y;
            s16 bx = ((GameTextBox*)box)->x;
            hudDrawRect(bx, by, bx + bw, by + bh, gGameTextBoxFillColor);
        }
        else
        {
            h7 = ((GameTextBox*)box)->height;
            w7 = ((GameTextBox*)box)->width;
            y7 = ((GameTextBox*)box)->y;
            x7 = ((GameTextBox*)box)->x;
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawHudBox(x7, y7, (s16)w7, (s16)h7, 0xff, 1);
        }
        break;
    case 1:
    {
        u16 bh = ((GameTextBox*)box)->height;
        u16 bw = ((GameTextBox*)box)->width;
        s16 by = ((GameTextBox*)box)->y;
        s16 bx = ((GameTextBox*)box)->x;
        hudDrawRect(bx, by, bx + bw, by + bh, gGameTextBoxFillColor);
    }
    break;
    case 6:
        if (strPtr == NULL)
        {
            return;
        }
        cur = gameTextGetCurBox();
        if (strPtr != NULL)
        {
            gameTextMeasureById(*(u16*)strPtr, 0, 0, &c6x0, &c6x1, &c6y0, &c6y1);
        }
        else if ((u32)boxId != 0)
        {
            gameTextMeasureStringBounds((char*)boxId, (int)((u8*)box - (u8*)gTextBoxes) / 0x20, &c6x0, &c6x1,
                                        &c6y0, &c6y1);
        }
        gameTextSetWindow(cur);
        hw = (c6x1 - c6x0) >> 1;
        hh = (c6y1 - c6y0) >> 1;
        cx = c6x0 + hw;
        cy = c6y0 + hh;
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(c6x0 - gGameTextBoxCornerInset),
                          (f32)(c6y0 - gGameTextBoxCornerInset), 0xff, 0x100, hw + gGameTextBoxCornerInset,
                          hh + gGameTextBoxCornerInset, 0);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cx, (f32)(c6y0 - gGameTextBoxCornerInset), 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 1);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(c6x0 - gGameTextBoxCornerInset), cy, 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 2);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cx, cy, 0xff, 0x100, hw + gGameTextBoxCornerInset,
                          hh + gGameTextBoxCornerInset, 3);
        break;
    case 0:
        drawScaledTexture(gGameTextBoxBgTexture, (f32)((GameTextBox*)box)->x, (f32)((GameTextBox*)box)->y, 0xff, 0x100,
                          ((GameTextBox*)box)->width, ((GameTextBox*)box)->height, 0);
        break;
    case 3:
        cur = gameTextGetCurBox();
        if (strPtr != NULL)
        {
            gameTextMeasureById(*(u16*)strPtr, 0, 0, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        else if ((u32)boxId != 0)
        {
            gameTextMeasureStringBounds((char*)boxId, (int)((u8*)box - (u8*)gTextBoxes) / 0x20, &c3x0, &c3x1,
                                        &c3y0, &c3y1);
        }
        gameTextSetWindow(cur);
        drawTexture(gSubtitleBoxTextures[0], (f32)(c3x0 - 0x16), (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100);
        drawScaledTexture(gSubtitleBoxTextures[1], (f32)c3x0, (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100,
                          c3x1 - c3x0, 0x24, 0);
        drawTexture(gSubtitleBoxTextures[2], (f32)c3x1, (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100);
        break;
    case 2:
        x2 = ((GameTextBox*)box)->x;
        w2 = ((GameTextBox*)box)->width;
        xw = x2 + w2;
        y2 = ((GameTextBox*)box)->y;
        half = w2 >> 1;
        if (half > 0xc)
        {
            half = 0xc;
        }
        rem = w2 - half * 2;
        if (rem < 0)
        {
            rem = 0;
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        drawTexture(gGameTextBoxFrameTextures[0], (f32)(x2 - 0x34), (f32)(y2 - 0x23),
                    ((GameTextBox*)box)->alpha, 0x100);
        drawTexture(gGameTextBoxFrameTextures[4], (f32)xw, (f32)(y2 - 0x23), ((GameTextBox*)box)->alpha, 0x100);
        if (half != 0)
        {
            drawScaledTexture(gGameTextBoxFrameTextures[1], (f32)x2, (f32)(y2 - 0x13),
                              ((GameTextBox*)box)->alpha, 0x100, half, 0x3a, 0);
            drawPartialTexture(gGameTextBoxFrameTextures[3], (f32)(xw - half), (f32)(y2 - 0x13),
                               ((GameTextBox*)box)->alpha, 0x100,
                               half, 0x3a, 0xc - half, 0);
        }
        if (rem != 0)
        {
            drawScaledTexture(gGameTextBoxFrameTextures[2], (f32)(x2 + half), (f32)(y2 - 0x13),
                              ((GameTextBox*)box)->alpha, 0x100, rem, 0x3a, 0);
        }
        break;
    case 4:
        boxDrawFn_8001c5ac((u16*)strPtr, boxId, (u8*)box);
        break;
    }
    ((GameTextBox*)box)->cursorX = savedX;
    ((GameTextBox*)box)->cursorY = savedY;
}

void boxDrawFn_8001c5ac(u16* strPtr, int boxId, u8* box)
{
    int x;
    int y;
    int alpha;
    int halfW;
    int halfH;
    int midX;
    int midY;

    alpha = ((GameTextBox*)box)->alpha;
    alpha |= ((GameTextBox*)box)->alpha;
    x = ((GameTextBox*)box)->x;
    y = ((GameTextBox*)box)->y;
    halfW = ((x + ((GameTextBox*)box)->width) - ((GameTextBox*)box)->x) >> 1;
    halfH = ((y + ((GameTextBox*)box)->height) - ((GameTextBox*)box)->y) >> 1;
    midX = x + halfW;
    midY = y + halfH;
    setTextColor(0, gGameTextBoxColorR & 0xff, gGameTextBoxColorG & 0xff, gGameTextBoxColorB & 0xff,
                 gGameTextBoxColorA & 0xff);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    drawScaledTexture(gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), (f32)(y - gGameTextBoxInset), alpha,
                      0x100, halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 0);
    drawScaledTexture(gGameTextBoxEdgeTexture, midX, (f32)(y - gGameTextBoxInset), alpha, 0x100,
                      halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 1);
    drawScaledTexture(gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), midY, alpha, 0x100,
                      halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 2);
    drawScaledTexture(gGameTextBoxEdgeTexture, midX, midY, alpha, 0x100, halfW + gGameTextBoxInset,
                      halfH + gGameTextBoxInset, 3);
}
