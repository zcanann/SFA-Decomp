/*
 * titlescreeninit (DLL 0x32) - boot/loading-screen front-end object.
 *
 * On initialise it unloads the prior map (0x3d), force-loads the title
 * map (0x3f) plus sun/moon and the game UI resources, inits the lock
 * icon, and warps to map 0x12. frameStart kicks the UI DLL (id 4) once,
 * one frame after init.
 *
 * runLoadingScreens advances a frame counter (lbl_803DD5EC) and fades
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

extern void hudDrawColored(int texture, int x, int y, u32* color, u32 scale, int flags);
extern void drawTexture(double x, double y, int texture, u32 alpha, u32 flags);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern int mapUnload(int mapId, int flags);
extern int loadMapAndParent(int mapId);
extern void loadSunAndMoon(void);
extern void gameUiLoadResources(void);
extern void lockIconInit(void);
extern void warpToMap(int idx, s8 transType);
extern void loadUiDll(int index);

extern int lbl_803A4438[];
extern u8 gDvdErrorPauseActive;
extern u8 lbl_803DC968;
extern u8 lbl_803DD5E8;
extern u32 lbl_803DD5EC;
extern s8 lbl_803DD5F0;
extern f32 lbl_803DD5F4;
extern f32 lbl_803E1CF0;
extern f32 lbl_803E1CF4;
extern f32 lbl_803E1CF8;
extern f32 lbl_803E1D00;

typedef struct LoadingScreenTexture
{
    u8 _00[0xa];
    u16 width;
    u16 height;
    u16 unk0e;
    u16 unk10;
    u8 _12[4];
    u8 format;
    u8 wrapS;
    u8 wrapT;
    u8 minFilter;
    u8 magFilter;
    u8 _1b[5];
    u32 texObj[8];
    int unk40;
    u32 bufferSize;
    u8 unk48;
    u8 _49[0x17];
    u8 imageData[1];
} LoadingScreenTexture;

void runLoadingScreens(void)
{
    int alpha;
    int textureSlot;
    u8 dvdErrorActive;
    u32 color;
    union
    {
        u32 word;
        u8 bytes[4];
    } colorBuf;

    if (lbl_803DD5EC < 0xf0)
    {
        if (lbl_803DD5EC < 0x1e)
        {
            alpha = (int)((lbl_803E1CF4 * lbl_803DD5EC) / lbl_803E1CF8);
        }
        else if (lbl_803DD5EC < 0xd2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((lbl_803E1CF4 * (f32)(0xf0 - lbl_803DD5EC)) / lbl_803E1CF8);
        }

        textureSlot = lbl_803A4438[0];
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
        *(char*)&colorBuf.bytes[3] = alpha;
        color = colorBuf.word;
        hudDrawColored(textureSlot, 0x85, 0xaa, &color, 0x100, 0);
    }
    else if (lbl_803DD5EC < 0x1e0)
    {
        if (lbl_803DD5EC < 0x10e)
        {
            alpha = (int)((lbl_803E1CF4 * (f32)(lbl_803DD5EC - 0xf0)) / lbl_803E1CF8);
        }
        else if (lbl_803DD5EC < 0x1c2)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((lbl_803E1CF4 * (f32)(0x1e0 - lbl_803DD5EC)) / lbl_803E1CF8);
        }
        drawTexture((double)(f32)(u32)((int)(0x280 - (u32) * (u16*)(lbl_803A4438[1] + 0xa)) >> 1),
                    (double)(f32)(u32)((int)(0x1e0 - (u32) * (u16*)(lbl_803A4438[1] + 0xc)) >> 1),
                    lbl_803A4438[1], alpha, 0x119);
    }
    else if (lbl_803DD5EC < 0x258)
    {
        if (lbl_803DD5EC < 0x1fe)
        {
            alpha = (int)((lbl_803E1CF4 * (f32)(lbl_803DD5EC - 0x1e0)) / lbl_803E1CF8);
        }
        else if (lbl_803DD5EC < 0x23a)
        {
            alpha = 0xff;
        }
        else
        {
            alpha = (int)((lbl_803E1CF4 * (f32)(0x258 - lbl_803DD5EC)) / lbl_803E1CF8);
        }
        drawTexture((double)(f32)(u32)((int)(0x280 - (u32) * (u16*)(lbl_803A4438[2] + 0xa)) >> 1),
                    (double)(f32)(u32)((int)(0x1e0 - (u32) * (u16*)(lbl_803A4438[2] + 0xc)) >> 1),
                    lbl_803A4438[2], alpha, 0x119);
    }

    dvdErrorActive = gDvdErrorPauseActive;
    if (dvdErrorActive != 0)
    {
        lbl_803DD5E8 = 1;
    }
    if (dvdErrorActive == 0)
    {
        lbl_803DD5EC++;
    }

    if ((lbl_803DD5E8 != 0) && (lbl_803DD5EC > 0x258) && (*(volatile u8*)&gDvdErrorPauseActive == 0))
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShowStr(gameTextGetStr(0x565), 0, 0x118, 300);
    }
}

void initLoadingScreenTextures(void)
{
    int textureSize;
    int arenaHi;
    GXTexObj* texObj;
    LoadingScreenTexture* textureHeader;
    LoadingScreenTexture** textureSlot;
    GXTexFmt textureFormat;
    u16 textureHeight;
    u16 textureWidth;
    int i;

    arenaHi = (int)OSGetArenaHi() - 0x40000;
    for (i = 0; i < 3; i++)
    {
        textureSlot = &((LoadingScreenTexture**)lbl_803A4438)[i];
        *textureSlot = (LoadingScreenTexture*)arenaHi;
        textureHeader = *textureSlot;
        textureHeader->unk40 = 0;
        textureHeader->unk48 = 0;
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
    lbl_803DD5EC = 0;
    lbl_803DD5E8 = 0;
}

void TitleScreenInit_render(void)
{
}

void TitleScreenInit_frameEnd(void)
{
}

int TitleScreenInit_frameStart(void)
{
    if (lbl_803DD5F0 != 0)
    {
        lbl_803DD5F0 = 0;
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
    lbl_803DD5F0 = 1;
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
