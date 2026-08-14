#include "dolphin/os.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXGet.h"
#include "main/textrender_api.h"
#include "main/fileio.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "dlls/object_descriptor.h"
#include "track/intersect_hud_api.h"
#include "main/dll/tricky.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_str_api.h"
#include "main/map_load.h"
#include "main/model_engine.h"
#include "main/rcp_dolphin_api.h"
#include "main/sky.h"
#include "main/dll/FRONT/dll_0032_titlescreeninit.h"

f32 lbl_803DD5F4;
s8 gTitleScreenInitFrameStartPending;
u32 gTitleScreenInitLoadingFrameCounter;
u8 gTitleScreenInitDvdErrorLatched;

#define TITLESCREENINIT_MAP_PRIOR 0x3d
#define TITLESCREENINIT_MAP_TITLE 0x3f
#define TITLESCREENINIT_MAP_WARP  0x12

#define TITLESCREENINIT_TEXT_DVD_ERROR 0x565

Texture* gTitleScreenInitLoadingTextures[4];
extern f32 lbl_803E1CF0;
extern f32 gTitleScreenInitAlphaMax;
extern f32 gTitleScreenInitFadeFrames;
extern f32 lbl_803E1D00;

void runLoadingScreens(void)
{
    Texture* textureSlot;
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
            alpha = ((gTitleScreenInitAlphaMax * (f32)(0xf0 - gTitleScreenInitLoadingFrameCounter)) /
                     gTitleScreenInitFadeFrames);
        }

        textureSlot = gTitleScreenInitLoadingTextures[0];
        if (gGameTextFontIsSjis != 0)
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
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(gTitleScreenInitLoadingFrameCounter - 0xf0)) /
                          gTitleScreenInitFadeFrames);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x1c2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(0x1e0 - gTitleScreenInitLoadingFrameCounter)) /
                          gTitleScreenInitFadeFrames);
        }
        drawTexture(gTitleScreenInitLoadingTextures[1],
                    (f32)(u32)((int)(0x280 - (u32)(gTitleScreenInitLoadingTextures[1])->width) >> 1),
                    (f32)(u32)((int)(0x1e0 - (u32)(gTitleScreenInitLoadingTextures[1])->height) >> 1), alpha,
                    0x119);
    }
    else if (gTitleScreenInitLoadingFrameCounter < 0x258)
    {
        int alpha;
        if (gTitleScreenInitLoadingFrameCounter < 0x1fe)
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(gTitleScreenInitLoadingFrameCounter - 0x1e0)) /
                          gTitleScreenInitFadeFrames);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x23a)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((gTitleScreenInitAlphaMax * (f32)(0x258 - gTitleScreenInitLoadingFrameCounter)) /
                          gTitleScreenInitFadeFrames);
        }
        drawTexture(gTitleScreenInitLoadingTextures[2],
                    (f32)(u32)((int)(0x280 - (u32)(gTitleScreenInitLoadingTextures[2])->width) >> 1),
                    (f32)(u32)((int)(0x1e0 - (u32)(gTitleScreenInitLoadingTextures[2])->height) >> 1), alpha,
                    0x119);
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

    if ((gTitleScreenInitDvdErrorLatched != 0) && (gTitleScreenInitLoadingFrameCounter > 0x258) &&
        (*(u8*)&gDvdErrorPauseActive == 0))
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShowStr(gameTextGetStr(TITLESCREENINIT_TEXT_DVD_ERROR), 0, 0x118, 300);
    }
}

static inline void initLoadingScreenTexturesBody(void)
{
    int textureSize;
    u16 textureHeight;
    int i;
    int arenaHi;
    Texture** textureSlot;
    Texture* textureHeader;
    GXTexObj* texObj;
    u16 textureWidth;
    GXTexFmt textureFormat;

    arenaHi = (int)OSGetArenaHi() - 0x40000;
    for (i = 0, textureSlot = gTitleScreenInitLoadingTextures; i < 3; textureSlot++, i++)
    {
        *textureSlot = (Texture*)arenaHi;
        textureHeader = *textureSlot;
        textureHeader->tmemAddr = 0;
        textureHeader->preloaded = 0;
        texObj = (GXTexObj*)textureHeader->gxTexObj;
        GXInitTexObj(texObj, (u8*)textureHeader + sizeof(Texture), textureHeader->width, textureHeader->height,
                     textureHeader->format, textureHeader->wrapS, textureHeader->wrapT, 0);
        GXInitTexObjLOD(texObj, textureHeader->minFilter, textureHeader->magFilter, lbl_803E1CF0, lbl_803E1CF0,
                        lbl_803E1CF0, 0, 0, 0);
        GXInitTexObjUserData(texObj, textureHeader);
        textureFormat = GXGetTexObjFmt(texObj);
        textureWidth = GXGetTexObjWidth(texObj);
        textureHeight = GXGetTexObjHeight(texObj);
        textureHeader->dataSize = GXGetTexBufferSize(textureWidth, textureHeight, textureFormat, 0, 0);
        textureSize = (*textureSlot)->dataSize + 0x60;
        arenaHi += textureSize;
    }
    gTitleScreenInitLoadingFrameCounter = 0;
    gTitleScreenInitDvdErrorLatched = 0;
}

void initLoadingScreenTextures(void)
{
    initLoadingScreenTexturesBody();
}

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
    mapUnload(TITLESCREENINIT_MAP_PRIOR, 0x10000000);
    setForceLoadImmediately();
    loadMapAndParent(TITLESCREENINIT_MAP_TITLE);
    clearForceLoadImmediately();
    loadSunAndMoon();
    gameUiLoadResources();
    camcontrol_initialiseTargetReticle();
    warpToMap(TITLESCREENINIT_MAP_WARP, 0);
}

ObjectDescriptor6 TitleScreenInit_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)TitleScreenInit_initialise,
    (ObjectDescriptorCallback)TitleScreenInit_release,
    0,
    (ObjectDescriptorCallback)TitleScreenInit_frameStart,
    (ObjectDescriptorCallback)TitleScreenInit_frameEnd,
    (ObjectDescriptorCallback)TitleScreenInit_render,
};
