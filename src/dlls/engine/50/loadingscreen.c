#include "dolphin/os.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXGet.h"
#include "main/textrender_api.h"
#include "main/fileio.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "track/intersect_hud_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_str_api.h"
#include "main/model_engine.h"
#include "main/dll/FRONT/dll_0032_titlescreeninit.h"

u32 gTitleScreenInitLoadingFrameCounter;
u8 gTitleScreenInitDvdErrorLatched;

#define TITLESCREENINIT_TEXT_DVD_ERROR 0x565

Texture* gTitleScreenInitLoadingTextures[4];

static void drawLoadingTexture(Texture* texture, int alpha)
{
    drawTexture(texture, (f32)(u32)((int)(0x280 - (u32)texture->width) >> 1),
                (f32)(u32)((int)(0x1e0 - (u32)texture->height) >> 1), alpha, 0x119);
}

static void initLoadingTexObj(GXTexObj* texObj, Texture* textureHeader)
{
    GXInitTexObjLOD(texObj, textureHeader->minFilter, textureHeader->magFilter, 0.0f, 0.0f, 0.0f, 0, 0, 0);
}

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
            alpha = ((255.0f * gTitleScreenInitLoadingFrameCounter) / 30.0f);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0xd2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = ((255.0f * (f32)(0xf0 - gTitleScreenInitLoadingFrameCounter)) / 30.0f);
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
            alpha = (int)((255.0f * (f32)(gTitleScreenInitLoadingFrameCounter - 0xf0)) / 30.0f);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x1c2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((255.0f * (f32)(0x1e0 - gTitleScreenInitLoadingFrameCounter)) / 30.0f);
        }
        drawLoadingTexture(gTitleScreenInitLoadingTextures[1], alpha);
    }
    else if (gTitleScreenInitLoadingFrameCounter < 0x258)
    {
        int alpha;
        if (gTitleScreenInitLoadingFrameCounter < 0x1fe)
        {
            alpha = (int)((255.0f * (f32)(gTitleScreenInitLoadingFrameCounter - 0x1e0)) / 30.0f);
        }
        else if (gTitleScreenInitLoadingFrameCounter < 0x23a)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((255.0f * (f32)(0x258 - gTitleScreenInitLoadingFrameCounter)) / 30.0f);
        }
        drawLoadingTexture(gTitleScreenInitLoadingTextures[2], alpha);
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
        texObj = &textureHeader->gxTexObj;
        GXInitTexObj(texObj, (u8*)textureHeader + sizeof(Texture), textureHeader->width, textureHeader->height,
                     textureHeader->format, textureHeader->wrapS, textureHeader->wrapT, 0);
        initLoadingTexObj(texObj, textureHeader);
        GXInitTexObjUserData(texObj, textureHeader);
        textureFormat = GXGetTexObjFmt(texObj);
        textureWidth = GXGetTexObjWidth(texObj);
        textureHeight = GXGetTexObjHeight(texObj);
        textureHeader->dataSize = GXGetTexBufferSize(textureWidth, textureHeight, textureFormat, 0, 0);
        textureSize = (*textureSlot)->dataSize + sizeof(Texture);
        arenaHi += textureSize;
    }
    gTitleScreenInitLoadingFrameCounter = 0;
    gTitleScreenInitDvdErrorLatched = 0;
}

void initLoadingScreenTextures(void)
{
    initLoadingScreenTexturesBody();
}
