/*
 * titlescreeninit (DLL 0x32) - boot/loading-screen front-end object.
 *
 * On initialise it unloads the prior map (0x3d), force-loads the title
 * map (0x3f) plus sun/moon and the game UI resources, inits the lock
 * icon, and warps to map 0x12. frameStart kicks the UI DLL (id 4) once,
 * one frame after init.
 *
 * runLoadingScreens advances a frame counter (gTitleScreenInitLoadingFrameCounter) and fades
 * three full-screen loading-screen textures in/out across three timed
 * windows, using a precomputed alpha ramp. A DVD read error
 * (gDvdErrorPauseActive) freezes the counter and, once past the third
 * window, shows a localized error string (text id 0x565).
 *
 * initLoadingScreenTextures carves the three textures out of the top of
 * the OS arena (OSGetArenaHi - 0x40000) and builds a GX texture object
 * for each.
 */
#include "main/dll/FRONT/dll_0032_n_rareware.h"
#include "dolphin/os.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXGet.h"
#include "main/dll/tricky.h"
#include "main/dll/dll_B4.h"
extern void hudDrawColored(int texture, int x, int y, u32* color, u32 scale, int flags);
extern void drawTexture(double x, double y, int texture, u32 alpha, u32 flags);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void* gameTextGetStr(int textId);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern int mapUnload(int mapId, int flags);
extern int loadMapAndParent(int mapId);
extern void loadSunAndMoon(void);
extern void warpToMap(int idx, s8 transType);
extern void loadUiDll(int index);
extern int gTitleScreenInitLoadingTextures[];
extern u8 gDvdErrorPauseActive;
extern u8 lbl_803DC968;
extern u8 gTitleScreenInitDvdErrorLatched;
extern u32 gTitleScreenInitLoadingFrameCounter;
extern s8 gTitleScreenInitFrameStartPending;
extern f32 lbl_803DD5F4;
extern f32 lbl_803E1CF0;
extern f32 gTitleScreenInitAlphaMax;
extern f32 gTitleScreenInitFadeFrames;
extern f32 lbl_803E1D00;

typedef struct LoadingScreenTexture
{
    u8 _00[0xa];
    u16 width;
    u16 height;
    u16 refCount;
    u16 unk10;
    u8 _12[4];
    u8 format;
    u8 wrapS;
    u8 wrapT;
    u8 minFilter;
    u8 magFilter;
    u8 _1b[5];
    u32 texObj[8];
    int tmemAddr;
    u32 bufferSize;
    u8 preloaded;
    u8 _49[0x17];
    u8 imageData[1];
} LoadingScreenTexture;

void runLoadingScreens(void)
{
    int textureSlot;
    u8 dvdErrorActive;
    u32 color;
    union
    {
        u32 word;
        u8 bytes[4];
    } colorBuf;

    if (gTitleScreenInitLoadingFrameCounter < 0xf0)
    {
        u8 alpha;
        if (gTitleScreenInitLoadingFrameCounter < 0x1e)
        {
            alpha = ((gTitleScreenInitAlphaMax * gTitleScreenInitLoadingFrameCounter) / gTitleScreenInitFadeFrames);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0xd2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = ((gTitleScreenInitAlphaMax * (f32)(0xf0 - gTitleScreenInitLoadingFrameCounter)) / gTitleScreenInitFadeFrames);
        }

        textureSlot = gTitleScreenInitLoadingTextures[0];
        if (lbl_803DC968 != 0)
        {
            colorBuf.bytes[0] = 0;
            colorBuf.bytes[1] = 0x46;
            colorBuf.bytes[2] = 0xff;
        }
        else
        {
            colorBuf.bytes[0] = 0xdc;
            colorBuf.bytes[1] = 0;
            colorBuf.bytes[2] = 0;
        }
        colorBuf.bytes[3] = alpha;
        color = colorBuf.word;
        hudDrawColored(textureSlot, 0x85, 0xaa, &color, 0x100, 0);
    }
    else if (gTitleScreenInitLoadingFrameCounter < 0x1e0)
    {
        int alpha;
        if (gTitleScreenInitLoadingFrameCounter < 0x10e)
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(gTitleScreenInitLoadingFrameCounter - 0xf0)) / gTitleScreenInitFadeFrames);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x1c2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(0x1e0 - gTitleScreenInitLoadingFrameCounter)) / gTitleScreenInitFadeFrames);
        }
        drawTexture((double)(f32)(u32)((int)(0x280 - (u32) * (u16*)(gTitleScreenInitLoadingTextures[1] + 0xa)) >> 1),
                    (double)(f32)(u32)((int)(0x1e0 - (u32) * (u16*)(gTitleScreenInitLoadingTextures[1] + 0xc)) >> 1),
                    gTitleScreenInitLoadingTextures[1], alpha, 0x119);
    }
    else if (gTitleScreenInitLoadingFrameCounter < 0x258)
    {
        int alpha;
        if (gTitleScreenInitLoadingFrameCounter < 0x1fe)
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(gTitleScreenInitLoadingFrameCounter - 0x1e0)) / gTitleScreenInitFadeFrames);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x23a)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(0x258 - gTitleScreenInitLoadingFrameCounter)) / gTitleScreenInitFadeFrames);
        }
        drawTexture((double)(f32)(u32)((int)(0x280 - (u32) * (u16*)(gTitleScreenInitLoadingTextures[2] + 0xa)) >> 1),
                    (double)(f32)(u32)((int)(0x1e0 - (u32) * (u16*)(gTitleScreenInitLoadingTextures[2] + 0xc)) >> 1),
                    gTitleScreenInitLoadingTextures[2], alpha, 0x119);
    }

    dvdErrorActive = gDvdErrorPauseActive;
    if (dvdErrorActive & 0xffu)
    {
        gTitleScreenInitDvdErrorLatched = 1;
    }
    if (dvdErrorActive == 0)
    {
        gTitleScreenInitLoadingFrameCounter++;
    }

    if ((gTitleScreenInitDvdErrorLatched != 0) && (gTitleScreenInitLoadingFrameCounter > 0x258) && (*(u8*)&gDvdErrorPauseActive == 0))
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShowStr(gameTextGetStr(0x565), 0, 0x118, 300);
    }
}

#pragma opt_propagation off
#pragma opt_common_subs off
#pragma inline_max_size(4000)
static inline void initLoadingScreenTexturesBody(void)
{
    int textureSize;
    u16 textureHeight;
    int i;
    int arenaHi;
    LoadingScreenTexture** textureSlot;
    LoadingScreenTexture* textureHeader;
    GXTexObj* texObj;
    u16 textureWidth;
    GXTexFmt textureFormat;

    arenaHi = (int)OSGetArenaHi() - 0x40000;
    for (i = 0, textureSlot = (LoadingScreenTexture**)gTitleScreenInitLoadingTextures; i < 3; textureSlot++, i++)
    {
        *textureSlot = (LoadingScreenTexture*)arenaHi;
        textureHeader = *textureSlot;
        textureHeader->tmemAddr = 0;
        textureHeader->preloaded = 0;
        texObj = (GXTexObj*)textureHeader->texObj;
        GXInitTexObj(texObj, textureHeader->imageData, textureHeader->width,
                     textureHeader->height, textureHeader->format,
                     textureHeader->wrapS, textureHeader->wrapT, 0);
        GXInitTexObjLOD(texObj, textureHeader->minFilter, textureHeader->magFilter,
                        lbl_803E1CF0, lbl_803E1CF0, lbl_803E1CF0, 0, 0, 0);
        GXInitTexObjUserData(texObj, textureHeader);
        textureFormat = GXGetTexObjFmt(texObj);
        textureWidth = GXGetTexObjWidth(texObj);
        textureHeight = GXGetTexObjHeight(texObj);
        textureHeader->bufferSize =
            GXGetTexBufferSize(textureWidth, textureHeight, textureFormat, 0, 0);
        textureSize = (*textureSlot)->bufferSize + 0x60;
        arenaHi += textureSize;
    }
    gTitleScreenInitLoadingFrameCounter = 0;
    gTitleScreenInitDvdErrorLatched = 0;
}

void initLoadingScreenTextures(void)
{
    initLoadingScreenTexturesBody();
}
#pragma inline_max_size reset
#pragma opt_common_subs reset
#pragma opt_propagation reset

void TitleScreenInit_render(void)
{
}

void TitleScreenInit_frameEnd(void)
{
}

int TitleScreenInit_frameStart(void)
{
    if (gTitleScreenInitFrameStartPending != 0)
    {
        gTitleScreenInitFrameStartPending = 0;
        lbl_803DD5F4 = lbl_803E1D00;
        loadUiDll(4);
    }
    return 0;
}

void TitleScreenInit_release(void)
{
}

void TitleScreenInit_initialise(void)
{
    gTitleScreenInitFrameStartPending = 1;
    lbl_803DD5F4 = lbl_803E1D00;
    mapUnload(0x3d, 0x10000000);
    setForceLoadImmediately();
    loadMapAndParent(0x3f);
    clearForceLoadImmediately();
    loadSunAndMoon();
    gameUiLoadResources();
    lockIconInit();
    warpToMap(0x12, 0);
}
