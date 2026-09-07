#define INTERSECT_HUD_RECT_COLOR_POINTER
#include "track/intersect_hud_api.h"
#undef INTERSECT_HUD_RECT_COLOR_POINTER
#include "main/gametext_shared_internal.h"
#include "main/gametext_api.h"
#include "main/gametext_task_api.h"
#include "main/texture.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "main/lightmap_text_color_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/rcp_dolphin_api.h"
#include "track/intersect_api.h"
#include "main/lightmap.h"
#include "main/gx_scissor_api.h"
#include "track/intersect_render_setup_api.h"

const GXColor gGameTextBoxFillColor = {0xFF, 0x40, 0x40, 0xFF};

int gSubtitleLineCount;
int gSubtitleBlockCount;
int gSubtitleElapsedFrames;
f32 gSubtitleCurTime;
int gSubtitleLineIndex;
int gSubtitleActive;
int gSubtitlesEnabled;
int gGameTextPendingTextId;
int gGameTextPendingDir;
u8 gSubtitleColorR;
u8 gSubtitleColorG;
u8 gSubtitleColorB;
u8 gSubtitleColorA;
int gGameTextSequenceMode;

/* Task (fortune-teller) text ids that may be shown; 0-terminated. */
s16 gGameTextTaskTextAllowList[12] = {
    0x69, 0x6d, 0x83, 0x490, 0x493, 0x492, 0x180, 0x47f, 0x1d, 0x20, 0x3c8, 0,
};

u16 gGameTextBoxCornerTexSrc[256] = {
    0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047,
    0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047,
    0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x0047, 0x1047, 0x1048, 0x1048, 0x2048,
    0x2048, 0x2048, 0x2048, 0x2048, 0x2048, 0x2048, 0x0047, 0x0047, 0x0047, 0x0047, 0x1048, 0x2048, 0x3058, 0x3059,
    0x4059, 0x4059, 0x4059, 0x4059, 0x4059, 0x4059, 0x4059, 0x4059, 0x0047, 0x0047, 0x0047, 0x1048, 0x2058, 0x3059,
    0x4059, 0x4059, 0x4059, 0x5059, 0x5059, 0x5059, 0x5059, 0x5059, 0x5059, 0x5059, 0x0047, 0x0047, 0x1047, 0x2058,
    0x3059, 0x4059, 0x5059, 0x5059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x0047,
    0x2048, 0x3059, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x0047, 0x0047, 0x3058, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x0047, 0x1048, 0x3059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x2048, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x2048, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x2048, 0x4059, 0x5059, 0x505A, 0x505A,
    0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x2048, 0x4059, 0x5059,
    0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x0047, 0x2048,
    0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x0047, 0x2048, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x0047, 0x2048, 0x4059, 0x5059, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A, 0x505A,
    0x505A, 0x505A, 0x505A, 0x505A,
};

u16 gGameTextBoxEdgeTexSrc[400] = {
    0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x1444, 0x3444, 0x1444, 0x0444,
     0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x3344,
     0x7455, 0xA98D, 0xADAE, 0xB5F0, 0x3444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444,
     0x0444, 0x0444, 0x0444, 0x3333, 0x7455, 0xB1CF, 0xBA11, 0xBA11, 0xC674, 0xCEB6, 0x3445, 0x0444, 0x0444, 0x0444,
     0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x6344, 0xB1CF, 0xBE53, 0xCAB5, 0xDB19, 0xDF39,
     0xF3DE, 0xFFFF, 0x2556, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x7455,
     0xBA11, 0xD6F7, 0xFBFF, 0xFFFF, 0xFFFF, 0xF3BE, 0xFFFF, 0xF7FF, 0x2555, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444,
     0x0444, 0x0444, 0x0444, 0x0444, 0x6445, 0xBA11, 0xE35B, 0xFFFF, 0xFFFF, 0xFFFF, 0xE79C, 0xCEB6, 0xE75B, 0xCAB6,
     0x2444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x3333, 0xB1EF, 0xD718, 0xFFFF, 0xFFFF,
     0xEB9D, 0xCED6, 0xBE52, 0xB1CF, 0xCA95, 0xB5EF, 0x2444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444, 0x0444,
     0x0444, 0xA14B, 0xCA95, 0xFFFF, 0xFFFF, 0xEFBD, 0xC695, 0xB610, 0xADAE, 0xA14B, 0xADAE, 0x9D2A, 0x94E8, 0x9929,
     0x9929, 0x9929, 0x9909, 0x9929, 0x9929, 0x992A, 0x4333, 0xADAE, 0xE77C, 0xFFFF, 0xF3DE, 0xCAB5, 0xB5F0, 0xA98D,
     0x9D2A, 0x94C7, 0x90A6, 0x8C84, 0x9908, 0xA9AD, 0xA9AD, 0xA9AD, 0xA98D, 0xA9AD, 0xA58D, 0xA9AE, 0x7333, 0xB1CF,
     0xF7DE, 0xFFFF, 0xDB19, 0xBE32, 0xADAE, 0xA14B, 0x98E8, 0x8C85, 0x8443, 0x8001, 0x94E8, 0xADCF, 0xADAF, 0xADCE,
     0xADCF, 0xADCE, 0xADCF, 0xADCF, 0x9908, 0xB611, 0xFBFF, 0xFFFF, 0xCAB6, 0xBA11, 0xA98C, 0x9D2A, 0x98E8, 0x8C65,
     0x90C6, 0x9508, 0xA14B, 0xA56C, 0xA14C, 0xA56C, 0xA14C, 0xA14C, 0xA16C, 0xA56C, 0x9D29, 0xBA12, 0xFFFF, 0xF3DE,
     0xC674, 0xB5F0, 0xA96C, 0xA12A, 0x94A7, 0x6465, 0x7585, 0x7586, 0x7596, 0x7596, 0x7596, 0x75A6, 0x75A6, 0x75A6,
     0x75A6, 0x75A6, 0x9909, 0xBA11, 0xFBFF, 0xE37B, 0xBA31, 0xB1CF, 0xA14B, 0x9D0A, 0x94C7, 0x5485, 0x5595, 0x5595,
     0x55A5, 0x55A5, 0x55A5, 0x55A5, 0x55A5, 0x55A5, 0x55A5, 0x55A5, 0x9D29, 0xB610, 0xEF9C, 0xEB5B, 0xD2D6, 0xCEB5,
     0xADAE, 0x98EA, 0x7233, 0x5586, 0x5596, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6,
     0xA14B, 0xCA95, 0xFFFF, 0xEFBD, 0xCA95, 0xBE32, 0xA96D, 0x98EA, 0x7233, 0x5485, 0x5595, 0x65A5, 0x65A5, 0x65A5,
     0x6595, 0x6595, 0x6595, 0x6595, 0x65A5, 0x6595, 0x94E7, 0xADAE, 0xF3DE, 0xEB9D, 0xC253, 0xB5EF, 0xA54B, 0x98EA,
     0x7233, 0x5586, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x8001, 0x8000, 0x9085, 0xEFBE, 0xC674, 0xB5F0, 0xA56C, 0x98EA, 0x7233, 0x5485, 0x6595, 0x65A5, 0x65A5, 0x6595, 0x6595,
     0x6595, 0x6595, 0x6595, 0x6595, 0x6595, 0xA2A5, 0x9EA4, 0x8423, 0xEFBE, 0xCA95, 0xB5F0, 0xA56C, 0x98EA,
     0x7233, 0x5586, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0xA2A6,
     0xAAE8, 0x8844, 0xEB9D, 0xCEB6, 0xB5F0, 0xA54C, 0x98EA, 0x7233, 0x5485, 0x6595, 0x65A5, 0x6595, 0x65A5,
     0x6595, 0x6595, 0x65A5, 0x65A5, 0x6595, 0x6595, 0xA6A6, 0xB32A, 0x8824, 0xE75B, 0xCEB6, 0xB5F0, 0xA54C,
     0x98EA, 0x7233, 0x5596, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6, 0x66A6,
};

Texture* gGameTextBoxFrameTextures[5];

static void gameTextDrawBoxEdges(u16* strPtr, int boxId, u8* box);

void subtitleStart(int x) {
    if (gSubtitlesEnabled != 0) {
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

static inline int gameTextIsTaskTextAllowed(int taskId) {
    s16* taskList;
    int count;

    taskList = gGameTextTaskTextAllowList;
    for (count = 0; count < 0xb; count++) {
        if (taskId == taskList[count]) {
            return 1;
        }
    }
    return 0;
}

void gameTextLoadTaskText(int taskId) {
    int textId;
    int dirId;

    if (gameTextGetTaskText(taskId, &textId, &dirId) != 0) {
        if (gSubtitlesEnabled == 0) {
            if (gameTextIsTaskTextAllowed(taskId) == 0) {
                return;
            }
        }

        gGameTextPendingTextId = textId;
        gGameTextPendingDir = dirId;
        if (dirId == 0x29) {
            loadGameTextSequence(dirId, textId);
            gGameTextSequenceMode = 1;
        } else {
            gGameTextSavedDir = getCurGameText();
            gameTextLoadDir(gGameTextPendingDir);
            gGameTextSequenceMode = 0;
        }
        gSubtitleActive = 1;
        gSubtitleColorR = 0xff;
        gSubtitleColorG = 0xff;
        gSubtitleColorB = 0xff;
        gSubtitleColorA = 0xff;
    }
}

int subtitleIsActive(void) {
    int ret;

    ret = 0;
    if (gSubtitlesEnabled != 0) {
        if (gSubtitleActive != 0) {
            ret = 1;
        }
    }
    return ret;
}

int setSubtitlesEnabled(int enabled) {
    int old = gSubtitlesEnabled;
    gSubtitlesEnabled = enabled;
    if (enabled == 0) {
        subtitleStop();
    }
    return old;
}

void subtitleInit(void) {
    int i;

    gSubtitleActive = 0;
    gSubtitlesEnabled = 1;
    gGameTextSavedDir = -1;

    for (i = 0; i < SUBTITLE_LINE_COUNT; i++) {
        gSubtitleBlocks[i] = NULL;
    }
}

void subtitleFreeBoxTextures(int mode) {
    switch (mode) {
    case 3:
        textureFree(gSubtitleBoxTextures[0]);
        textureFree(gSubtitleBoxTextures[1]);
        textureFree(gSubtitleBoxTextures[2]);
        break;
    }
}

void subtitleLoadBoxTextures(int mode) {
    switch (mode) {
    case 3:
        gSubtitleBoxTextures[0] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_LEFT);
        gSubtitleBoxTextures[1] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_MID);
        gSubtitleBoxTextures[2] = textureLoadAsset(TEXTRENDER_TEXTURE_SUBTITLE_BOX_RIGHT);
        break;
    }
}

void gameTextDrawBox(struct GameTextDef* strPtr, int boxId, GameTextBox* box) {
    GXColor fillColor7;
    GXColor fillColor1;
    int cornerMaxY;
    int cornerMinY;
    int cornerMaxX;
    int cornerMinX;
    int subtitleMaxY;
    int subtitleMinY;
    int subtitleMaxX;
    int subtitleMinX;
    s16 savedY;
    s16 savedX;
    u16 boxFlags;
    u8* window;
    int cornerCenterY;
    int cornerCenterX;
    int cornerHalfHeight;
    int cornerHalfWidth;
    s16 hudX;
    s16 hudY;
    u16 hudWidth;
    u16 hudHeight;
    int frameY;
    int frameWidth;
    int frameRight;
    s16 frameX;
    int edgeWidth;
    int middleWidth;

    savedX = box->cursorX;
    savedY = box->cursorY;
    boxFlags = box->flags;
    if (boxFlags & 1) {
        return;
    }
    box->flags = boxFlags | 1;
    switch (box->style) {
    case 5:
        return;
    case 7:
        if (getCurGameText() == 3) {
            u16 bh = box->height;
            u16 bw = box->width;
            s16 by = box->y;
            s16 bx = box->x;
            fillColor7 = gGameTextBoxFillColor;
            hudDrawRect(bx, by, bx + bw, by + bh, &fillColor7);
        } else {
            hudHeight = box->height;
            hudWidth = box->width;
            hudY = box->y;
            hudX = box->x;
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawHudBox(hudX, hudY, (s16)hudWidth, (s16)hudHeight, 0xff, 1);
        }
        break;
    case 1: {
        u16 bh = box->height;
        u16 bw = box->width;
        s16 by = box->y;
        s16 bx = box->x;
        fillColor1 = gGameTextBoxFillColor;
        hudDrawRect(bx, by, bx + bw, by + bh, &fillColor1);
    } break;
    case 6: {
        if (strPtr == NULL) {
            return;
        }
        window = gameTextGetCurBox();
        if (strPtr != NULL) {
            gameTextMeasureById(*(u16*)strPtr, 0, 0, &cornerMinX, &cornerMaxX, &cornerMinY, &cornerMaxY);
        } else if ((u32)boxId != 0) {
            gameTextMeasureStringBounds((char*)boxId, (int)((u8*)box - (u8*)gTextBoxes) / 0x20, &cornerMinX,
                                        &cornerMaxX, &cornerMinY, &cornerMaxY);
        }
        gameTextSetWindow(window);
        cornerHalfWidth = (cornerMaxX - cornerMinX) >> 1;
        cornerHalfHeight = (cornerMaxY - cornerMinY) >> 1;
        cornerCenterX = cornerMinX + cornerHalfWidth;
        cornerCenterY = cornerMinY + cornerHalfHeight;
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(cornerMinX - gGameTextBoxCornerInset),
                          (f32)(cornerMinY - gGameTextBoxCornerInset), 0xff, 0x100,
                          cornerHalfWidth + gGameTextBoxCornerInset, cornerHalfHeight + gGameTextBoxCornerInset, 0);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cornerCenterX, (f32)(cornerMinY - gGameTextBoxCornerInset),
                          0xff, 0x100, cornerHalfWidth + gGameTextBoxCornerInset,
                          cornerHalfHeight + gGameTextBoxCornerInset, 1);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(cornerMinX - gGameTextBoxCornerInset), cornerCenterY, 0xff,
                          0x100, cornerHalfWidth + gGameTextBoxCornerInset, cornerHalfHeight + gGameTextBoxCornerInset,
                          2);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cornerCenterX, cornerCenterY, 0xff, 0x100,
                          cornerHalfWidth + gGameTextBoxCornerInset, cornerHalfHeight + gGameTextBoxCornerInset, 3);
        break;
    }
    case 0:
        drawScaledTexture(gGameTextBoxBgTexture, (f32)box->x, (f32)box->y, 0xff, 0x100, box->width, box->height, 0);
        break;
    case 3: {
        window = gameTextGetCurBox();
        if (strPtr != NULL) {
            gameTextMeasureById(*(u16*)strPtr, 0, 0, &subtitleMinX, &subtitleMaxX, &subtitleMinY, &subtitleMaxY);
        } else if ((u32)boxId != 0) {
            gameTextMeasureStringBounds((char*)boxId, (int)((u8*)box - (u8*)gTextBoxes) / 0x20, &subtitleMinX,
                                        &subtitleMaxX, &subtitleMinY, &subtitleMaxY);
        }
        gameTextSetWindow(window);
        drawTexture(gSubtitleBoxTextures[0], (f32)(subtitleMinX - 0x16), (f32)(subtitleMinY - 9), box->alpha, 0x100);
        drawScaledTexture(gSubtitleBoxTextures[1], (f32)subtitleMinX, (f32)(subtitleMinY - 9), box->alpha, 0x100,
                          subtitleMaxX - subtitleMinX, 0x24, 0);
        drawTexture(gSubtitleBoxTextures[2], (f32)subtitleMaxX, (f32)(subtitleMinY - 9), box->alpha, 0x100);
        break;
    }
    case 2:
        frameX = box->x;
        frameWidth = box->width;
        frameRight = frameX + frameWidth;
        frameY = box->y;
        edgeWidth = frameWidth >> 1;
        if (edgeWidth > 0xc) {
            edgeWidth = 0xc;
        }
        middleWidth = frameWidth - edgeWidth * 2;
        if (middleWidth < 0) {
            middleWidth = 0;
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        drawTexture(gGameTextBoxFrameTextures[0], (f32)(frameX - 0x34), (f32)(frameY - 0x23), box->alpha, 0x100);
        drawTexture(gGameTextBoxFrameTextures[4], (f32)frameRight, (f32)(frameY - 0x23), box->alpha, 0x100);
        if (edgeWidth != 0) {
            drawScaledTexture(gGameTextBoxFrameTextures[1], (f32)frameX, (f32)(frameY - 0x13), box->alpha, 0x100,
                              edgeWidth, 0x3a, 0);
            drawPartialTexture(gGameTextBoxFrameTextures[3], (f32)(frameRight - edgeWidth), (f32)(frameY - 0x13),
                               box->alpha, 0x100, edgeWidth, 0x3a, 0xc - edgeWidth, 0);
        }
        if (middleWidth != 0) {
            drawScaledTexture(gGameTextBoxFrameTextures[2], (f32)(frameX + edgeWidth), (f32)(frameY - 0x13), box->alpha,
                              0x100, middleWidth, 0x3a, 0);
        }
        break;
    case 4:
        gameTextDrawBoxEdges((u16*)strPtr, boxId, (u8*)box);
        break;
    }
    box->cursorX = savedX;
    box->cursorY = savedY;
}

static void gameTextDrawBoxEdges(u16* strPtr, int boxId, u8* box) {
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
    gxTevResetStages();
    gxTevTextureTimesColor1Stage();
    gxTevCommitStages();
    drawScaledTexture(gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), (f32)(y - gGameTextBoxInset), alpha, 0x100,
                      halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 0);
    drawScaledTexture(gGameTextBoxEdgeTexture, midX, (f32)(y - gGameTextBoxInset), alpha, 0x100,
                      halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 1);
    drawScaledTexture(gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), midY, alpha, 0x100,
                      halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 2);
    drawScaledTexture(gGameTextBoxEdgeTexture, midX, midY, alpha, 0x100, halfW + gGameTextBoxInset,
                      halfH + gGameTextBoxInset, 3);
}

Texture* gSubtitleBoxTextures[3];
