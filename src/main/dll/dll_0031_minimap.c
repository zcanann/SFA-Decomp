/*
 * minimap (DLL 0x31) - the in-world minimap / compass HUD.
 *
 * Minimap_update() resolves the player's current map cell against
 * gMinimapCellTable, picks the texture asset to display, animates the
 * box open/close and fade, and renders one of three view modes (the
 * view-mode selector: 0 = scrollable map texture, 1 = radar/blip
 * view, 2 = area-name text). The per-frame input handler toggles the
 * map (event 0xC8D), cycles the view mode with D-pad left/right, drives
 * zoom (modes via powfCoreFast) and the compass blip, and plays the
 * associated UI sfx.
 *
 * The HUD is suppressed (and faded out) when the camera is in mode
 * 0x44, the viewport is letterboxed, the player model is hidden, or the
 * pause menu is up. Minimap_initialise()/Minimap_release() own the
 * texture buffers (minimapTexture, the compass at lbl_803DD940) and the
 * 2-slot live-objects table at lbl_803DBBC8.
 */
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/gamebits.h"
#include "dolphin/gx/GXCull.h"
#include "main/pad.h"
#include "main/camera.h"
#include "main/objlib.h"
#include "main/sfa_extern_decls.h"
#include "main/lightmap.h"

typedef struct MinimapRow
{
    s16 x0, x1, z0, z1, y0, y1;
    u16 gameBit;
    u8 texU, texV;
    u16 mapId;
    u8 swap;
    u8 pad13;
} MinimapRow;

typedef struct MinimapMapEntry
{
    MinimapRow* rows;
    u16 gameBit;
    u8 cellId;
    u8 count;
} MinimapMapEntry;

extern MinimapMapEntry gMinimapCellTable[];

void fn_80133718(void);
void fn_8013351C(void);


extern void* Obj_GetPlayerObject(void);
extern s16 Camera_GetViewportYOffset(void);
extern int objIsCurModelNotZero(int obj);
extern void* gameTextGetBox(int box);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShow(int a);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern void hudDrawTriangle(f32 x0, f32 y0, f32 x1, f32 y1, f32 x2, f32 y2, u32* color);
extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32* color);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int scale, u32 w, u32 h, u32 u, u32 v);
extern void drawHudBox(s16 id, s16 x, s16 y, s16 w, int alpha, u8 p6);
extern void gameTextSetCursor(int a, int b, int c);
extern int gameTextGetCharset(void);
extern void gameTextSetCharset(int charset, int flags);
extern u8 gMinimapEnabled;
extern u8 lbl_803DD7BA;
extern s16 lbl_803DD7A2;
extern s16 lbl_803DBA6E;
extern u8 gMinimapAreaNameDelay;
extern int lbl_803DD934;
extern u8 pauseMenuState;
extern u8 lbl_803DD75B;
extern s16 gMinimapFadeAlpha;
extern s16 gMinimapContentAlpha;
extern u32 lbl_803DD938;
extern void* lbl_803DD92C;
extern void* minimapTexture;
extern void* lbl_803DD940;
extern u8 gMinimapTexU;
extern u8 gMinimapTexV;
extern s16 gMinimapRegionMaxX;
extern s16 gMinimapRegionMaxZ;
extern s16 gMinimapRegionMinX;
extern s16 gMinimapRegionMinZ;
extern s8 gMinimapAxisSwap;
extern s8 gMinimapViewMode;
extern int gMinimapBoxWidth;
extern int gMinimapBoxHeight;
extern f32 gMinimapZoom;
extern f32 gMinimapMinZoom;
extern f32 gMinimapMaxZoom;
extern f32 gMinimapWorldToTexScale;
extern f32 gMinimapArrowScale2;
extern f32 gMinimapArrowScale1;
extern f32 gMinimapArrowScale0;
extern u8 framesThisStep;
extern u32 gMinimapBaseColor;
extern const f32 gMinimapZero;
extern f32 gMinimapF50;
extern f32 gMinimapF256;
extern f32 gMinimapFNeg10;
extern f32 gMinimapFNeg6_67;
extern f32 gMinimapPi;
extern f32 gMinimapF32768;
extern f32 gMinimapFNeg6;
extern f32 gMinimapFNeg4;
extern f32 gMinimapF32;
extern f32 gMinimapF44;
extern f32 gMinimapF52;
extern f32 gMinimapF48;
extern f32 gMinimapF28;
extern f32 gMinimapF22;
extern f32 gMinimapF68;
extern f32 gMinimapF74;

#pragma scheduling off
#pragma peephole off
extern void* lbl_803DBBC8[2];
extern void Obj_FreeObject(u8* obj);
extern int Obj_AllocObjectSetup(int a, int b);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
extern f32 gMinimapFNeg15;
extern f32 gMinimapFNeg9_8;
extern f32 gMinimapFNeg40;
extern f32 gMinimapF0_05;
extern void viewFn_80129cbc(f32 a, f32 b, f32 c);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objRender(int a, int b, int c, int d, void* obj, int f);
extern void* Obj_GetActiveModel(u8* obj);
extern u8 gMinimapBlipPulse;
extern f32 gMinimapF110;
extern f32 gMinimapF43;
extern f32 gMinimapF390;
extern f32 timeDelta;
extern void Sfx_StopFromObject(u32 obj, u32 sfxId);
extern u32 gMinimapCompassColor;
extern f32 gMinimapCompassPhase;
extern f32 gMinimapBlipNearDist;
extern f32 gMinimapF65536;
extern f32 gMinimapF60;
extern f32 gMinimapTwo;
extern f32 gMinimapF24576;
extern f32 gMinimapFNeg24576;
extern u32 getButtonsHeld(int port);
extern f32 powfCoreFast(f32 base, f32 exp);
extern int getAngle(float y, float x);
extern u8 gMinimapZoomSfxActive;
extern u8 gMinimapRadarInited;
extern s8 gMinimapSavedViewMode;
extern int gMinimapPrevAreaNameId;
extern f32 gMinimapZoomInRate;
extern f32 gMinimapZoomOutRate;
extern f32 gMinimapZoomStepMin;
extern f32 gMinimapZoomStepMax;
extern f32 gMinimapZoomStep;
extern f32 gMinimapFltMax;
extern f32 gMinimapOne;
extern f32 gMinimapBlipVeryNearDist;

int Minimap_update(void)
{
    u8* player;
    int marker;
    u8 found;
    u8 cell;
    int yi;
    u8 k;
    u8 i;
    MinimapRow* row;
    MinimapRow* r2;
    MinimapRow* rows;
    int v;
    u8 j;
    int n;
    int w;
    u16* box;
    int cs;
    int boxW;
    int boxH;
    int xc;
    int xr;
    int xl;
    s16 m;
    int sv;
    u32 texW, texH;
    f32 s2, fz, panx, yrel, xrel, pany, ox, oy, t, e, a, b, uq, cx, cy, frac, fx;
    u32 vv, u;
    f32 c2, s1, c1, c3, s3, fv;
    u32 col;
    u32 col2;
    u32 cwRect;
    u32 cwTri1;
    u32 cwTri2;
    u32 cwL;
    u32 cwR;
    u32 cwM;
    u32 cwB;

    marker = 0;
    i = 0;
    k = 0;
    found = 0;
    oy = ox = gMinimapZero;
    col = gMinimapBaseColor;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (((GameObject*)player)->anim.parent != NULL)
        {
            cell = ((GameObject*)((GameObject*)player)->anim.parent)->anim.mapEventSlot;
        }
        else
        {
            cell = coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
        }
        while (!found && i < 0x19)
        {
            if (cell == gMinimapCellTable[i].cellId && GameBit_Get(gMinimapCellTable[i].gameBit) != 0)
            {
                found = 1;
            }
            else
            {
                i++;
            }
        }
        if (found != 0)
        {
            rows = gMinimapCellTable[i].rows;
            if (rows->swap != 0)
            {
                fx = ((GameObject*)player)->anim.worldPosZ;
                fz = ((GameObject*)player)->anim.worldPosX;
                gMinimapAxisSwap = 1;
            }
            else
            {
                fx = ((GameObject*)player)->anim.worldPosX;
                fz = ((GameObject*)player)->anim.worldPosZ;
                gMinimapAxisSwap = 0;
            }
            yi = (int)((GameObject*)player)->anim.worldPosY;
            for (; k < gMinimapCellTable[i].count; k++)
            {
                row = &rows[k];
                if (fx >= row->x0 && fx < row->x1 &&
                    fz >= row->z0 && fz < row->z1 &&
                    (s16)yi >= row->y0 && (s16)yi < row->y1 &&
                    GameBit_Get(row->gameBit) != 0)
                {
                    j = 0;
                    v = rows[k].mapId;
                    if (v != 0)
                    {
                        marker = v;
                    }
                    if ((int)lbl_803DD92C == v)
                    {
                        gMinimapRegionMaxX = -0x8000;
                        gMinimapRegionMaxZ = -0x8000;
                        gMinimapRegionMinX = 0x7fff;
                        gMinimapRegionMinZ = 0x7fff;
                        for (; j < gMinimapCellTable[i].count; j++)
                        {
                            if (marker == rows[j].mapId)
                            {
                                gMinimapRegionMinX = (rows[j].x0 < gMinimapRegionMinX) ? rows[j].x0 : gMinimapRegionMinX;
                                gMinimapRegionMaxX = (rows[j].x1 > gMinimapRegionMaxX) ? rows[j].x1 : gMinimapRegionMaxX;
                                gMinimapRegionMinZ = (rows[j].z0 < gMinimapRegionMinZ) ? rows[j].z0 : gMinimapRegionMinZ;
                                gMinimapRegionMaxZ = (rows[j].z1 > gMinimapRegionMaxZ) ? rows[j].z1 : gMinimapRegionMaxZ;
                            }
                        }
                        gMinimapTexU = rows[k].texU;
                        gMinimapTexV = rows[k].texV;
                    }
                    break;
                }
            }
        }
        if ((gMinimapEnabled == 0 && lbl_803DD7BA == 0) || GameBit_Get(0x58d) != 0)
        {
            marker = 0;
        }
        if ((*gCameraInterface)->getMode() == 0x44 ||
            (gMinimapEnabled == 0 && lbl_803DD7BA == 0) ||
            Camera_GetViewportYOffset() != 0 ||
            (((GameObject*)player)->objectFlags & 0x1000) != 0 ||
            objIsCurModelNotZero((int)player) == 0 ||
            pauseMenuState != 0 || lbl_803DD75B != 0)
        {
            marker = 0;
            gMinimapFadeAlpha -= 0x20;
            n = gMinimapFadeAlpha;
            if (n < 0) n = 0;
            else if (n > 0xff) n = 0xff;
            gMinimapFadeAlpha = n;
            gMinimapBoxWidth -= 10;
            n = gMinimapBoxWidth;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            gMinimapBoxWidth = n;
            gMinimapBoxHeight -= 10;
            n = gMinimapBoxHeight;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            gMinimapBoxHeight = n;
        }
        else
        {
            gMinimapBoxHeight += 10;
            n = gMinimapBoxHeight;
            if (n < 0) n = 0;
            else if (n > 100) n = 100;
            gMinimapBoxHeight = n;
            gMinimapFadeAlpha += 0x20;
            n = gMinimapFadeAlpha;
            if (n < 0) n = 0;
            else if (n > 0xff) n = 0xff;
            gMinimapFadeAlpha = n;
        }
        if ((int)lbl_803DD92C == marker)
        {
            gMinimapContentAlpha += 0x20;
            gMinimapContentAlpha =
                (s16)((gMinimapContentAlpha < 0)
                          ? 0
                          : (s16)((gMinimapContentAlpha > gMinimapFadeAlpha) ? gMinimapFadeAlpha
                                                                             : gMinimapContentAlpha));
        }
        else
        {
            gMinimapContentAlpha -= 0x20;
            if (gMinimapContentAlpha < 0)
            {
                gMinimapContentAlpha = 0;
                if (minimapTexture != NULL)
                {
                    textureFree(minimapTexture);
                    minimapTexture = NULL;
                    lbl_803DD92C = NULL;
                }
                if (marker != 0)
                {
                    minimapTexture = textureLoadAsset(marker);
                    lbl_803DD92C = (void*)marker;
                }
            }
        }
        if (gMinimapFadeAlpha != 0)
        {
            box = gameTextGetBox(0x83);
            if (gMinimapViewMode == 2 && lbl_803DD7A2 != 0 && lbl_803DBA6E > -1)
            {
                w = 200;
            }
            else
            {
                w = 0x78;
            }
            if (gMinimapBoxWidth < w)
            {
                gMinimapBoxWidth += framesThisStep * 8;
                gMinimapBoxWidth = (gMinimapBoxWidth < w) ? gMinimapBoxWidth : w;
            }
            else
            {
                gMinimapBoxWidth -= framesThisStep * 8;
                gMinimapBoxWidth = (gMinimapBoxWidth > w) ? gMinimapBoxWidth : w;
            }
            box[4] = (u16)(gMinimapBoxWidth - 8);
            lbl_803DD938 = 0x1b8 - gMinimapBoxHeight;
            ((s16*)box)[0xb] = lbl_803DD938;
            drawHudBox(0x32, lbl_803DD938, gMinimapBoxWidth, gMinimapBoxHeight,
                       gMinimapFadeAlpha & 0xff, 1);
            GXSetScissor(0x32, lbl_803DD938, gMinimapBoxWidth, gMinimapBoxHeight);
            switch (gMinimapViewMode)
            {
            case 0:
                if (minimapTexture != NULL)
                {
                    texW = ((Texture*)minimapTexture)->width;
                    texH = ((Texture*)minimapTexture)->height;
                    gMinimapWorldToTexScale = texW / (f32)(gMinimapRegionMaxX - gMinimapRegionMinX);
                    boxW = gMinimapBoxWidth;
                    a = (f32)boxW / (f32)texW;
                    boxH = gMinimapBoxHeight;
                    b = (f32)boxH / (f32)texH;
                    a = (a < b) ? a : b;
                    a = (a < gMinimapMaxZoom) ? a : gMinimapMaxZoom;
                    gMinimapMinZoom = a;
                    if (gMinimapAxisSwap != 0)
                    {
                        xrel = -((GameObject*)player)->anim.worldPosZ + gMinimapRegionMaxX;
                        yrel = ((GameObject*)player)->anim.worldPosX - gMinimapRegionMinZ;
                    }
                    else
                    {
                        xrel = -((GameObject*)player)->anim.worldPosX + gMinimapRegionMaxX;
                        yrel = -((GameObject*)player)->anim.worldPosZ + gMinimapRegionMaxZ;
                    }
                    e = boxW - texW * gMinimapZoom;
                    e = e * 0.5f;
                    t = 0.0f;
                    t = (t > e) ? t : e;
                    panx = -t;
                    e = boxH - texH * gMinimapZoom;
                    e = e * 0.5f;
                    t = 0.0f;
                    t = (t > e) ? t : e;
                    pany = -t;
                    t = 0.0f;
                    if (t == panx)
                    {
                        a = gMinimapZoom * (xrel * gMinimapWorldToTexScale) - (f32)(boxW / 2);
                        t = (t > a) ? t : a;
                        t = (t < (b = texW * gMinimapZoom - boxW)) ? t : b;
                        ox = t;
                    }
                    t = 0.0f;
                    if (t == pany)
                    {
                        a = gMinimapZoom * (yrel * gMinimapWorldToTexScale) - (f32)(boxH / 2);
                        t = (t > a) ? t : a;
                        t = (t < (b = texH * gMinimapZoom - boxH)) ? t : b;
                        oy = t;
                    }
                    uq = ox / gMinimapZoom;
                    u = uq;
                    frac = gMinimapZoom * (uq - (f32)u);
                    uq = oy / gMinimapZoom;
                    vv = uq;
                    fv = gMinimapZoom * (uq - vv);
                    ((u8*)&col)[3] = gMinimapContentAlpha;
                    ((u8*)&col)[0] = 0x20;
                    ((u8*)&col)[1] = 0x4d;
                    ((u8*)&col)[2] = 0x84;
                    cwRect = col;
                    hudDrawRect(0x32, lbl_803DD938, boxW + 0x32, lbl_803DD938 + boxH, &cwRect);
                    drawPartialTexture(minimapTexture,
                                       (gMinimapF50 - panx) - frac,
                                       ((f32)(int)lbl_803DD938 - pany) - fv,
                                       gMinimapContentAlpha & 0xff,
                                       (int)(gMinimapF256 * *(f32*)&gMinimapZoom),
                                       texW - u, texH - vv, u, vv);
                    cx = 0.5f +
                        ((gMinimapZoom * (xrel * gMinimapWorldToTexScale) + gMinimapF50) - ox - panx);
                    cy = 0.5f +
                        ((gMinimapZoom * (yrel * gMinimapWorldToTexScale) + (f32)(int)lbl_803DD938) - oy - pany);
                    ((u8*)&col)[3] = gMinimapContentAlpha;
                    ((u8*)&col)[0] = 0;
                    ((u8*)&col)[1] = 0;
                    ((u8*)&col)[2] = 0;
                    gMinimapArrowScale0 = gMinimapFNeg10;
                    fv = gMinimapFNeg6_67;
                    gMinimapArrowScale1 = fv;
                    gMinimapArrowScale2 = fv;
                    c1 = gMinimapArrowScale0 * mathSinf(gMinimapPi * (f32)((GameObject*)player)->anim.rotX / gMinimapF32768);
                    s1 = gMinimapArrowScale0 * mathCosf(gMinimapPi * (f32)((GameObject*)player)->anim.rotX / gMinimapF32768);
                    c2 = gMinimapArrowScale1 *
                        mathSinf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / gMinimapF32768);
                    s2 = gMinimapArrowScale1 *
                        mathCosf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / gMinimapF32768);
                    c3 = gMinimapArrowScale2 *
                        mathSinf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / gMinimapF32768);
                    s3 = gMinimapArrowScale2 *
                        mathCosf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / gMinimapF32768);
                    cwTri1 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri1);
                    ((u8*)&col)[3] = gMinimapContentAlpha;
                    ((u8*)&col)[0] = 0xff;
                    ((u8*)&col)[1] = 0xff;
                    ((u8*)&col)[2] = 0;
                    c1 = gMinimapFNeg6 * mathSinf(gMinimapPi * (f32)((GameObject*)player)->anim.rotX / gMinimapF32768);
                    s1 = gMinimapFNeg6 * mathCosf(gMinimapPi * (f32)((GameObject*)player)->anim.rotX / gMinimapF32768);
                    c2 = gMinimapFNeg4 *
                        mathSinf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / gMinimapF32768);
                    s2 = gMinimapFNeg4 *
                        mathCosf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / gMinimapF32768);
                    c3 = gMinimapFNeg4 *
                        mathSinf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / gMinimapF32768);
                    s3 = gMinimapFNeg4 *
                        mathCosf(gMinimapPi * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / gMinimapF32768);
                    cwTri2 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri2);
                }
                else
                {
                    gameTextSetCursor(box[1], box[5], 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box[4] = (u16)((n > 2) ? n : 2);
                    box[4] = (box[4] < box[0]) ? box[4] : box[0];
                    n = gMinimapBoxHeight;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    cs = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x458);
                    gameTextSetCharset(cs, 3);
                    gameTextResetCursor(2);
                }
                break;
            case 1:
                fn_80133718();
                if ((u32)lbl_803DD934 == 0)
                {
                    fn_8013351C();
                    gameTextSetCursor(box[1], box[5], 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box[4] = (u16)((n > 2) ? n : 2);
                    box[4] = (box[4] < box[0]) ? box[4] : box[0];
                    n = gMinimapBoxHeight;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    cs = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x459);
                    gameTextSetCharset(cs, 3);
                    gameTextResetCursor(2);
                }
                break;
            case 2:
                if (lbl_803DD7A2 != 0 && lbl_803DBA6E > -1)
                {
                    if (gMinimapAreaNameDelay == 0)
                    {
                        gameTextSetCursor(box[1], box[5], 1);
                        gameTextResetCursor(1);
                        box[4] = gMinimapBoxWidth;
                        box[5] = gMinimapBoxHeight;
                        gameTextSetCursor(box[1], box[5], 2);
                        gameTextSetColor(0, 0xff, 0, lbl_803DD7A2 & 0xff);
                        gameTextShow(lbl_803DBA6E + 10000);
                        gameTextResetCursor(2);
                    }
                }
                else if (gMinimapEnabled != 0)
                {
                    fn_8013351C();
                    gameTextSetCursor(box[1], box[5], 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box[4] = (u16)((n > 2) ? n : 2);
                    box[4] = (box[4] < box[0]) ? box[4] : box[0];
                    n = gMinimapBoxHeight;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    cs = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x45a);
                    gameTextSetCharset(cs, 3);
                    gameTextResetCursor(2);
                }
                break;
            }
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawTexture(lbl_803DD940, gMinimapF32, (f32)(int)(lbl_803DD938 - 0x14),
                        gMinimapFadeAlpha & 0xff, 0x100);
            if (gMinimapFadeAlpha != 0)
            {
                ((u8*)&col2)[3] = gMinimapContentAlpha;
                ((u8*)&col2)[0] = 0xff;
                ((u8*)&col2)[1] = 0xff;
                ((u8*)&col2)[2] = 0;
                xc = (s16)(lbl_803DD938 - 4);
                if (gMinimapViewMode == 0 && minimapTexture != NULL)
                {
                    if (gMinimapZoom < gMinimapMaxZoom)
                    {
                        t = (f32)(sv = xc - 0x14);
                        cwL = col2;
                        hudDrawTriangle(gMinimapF44, t,
                                        gMinimapF52, (f32)sv,
                                        gMinimapF48, (f32)(xc - 0x1a), &cwL);
                    }
                    if (gMinimapZoom > gMinimapMinZoom)
                    {
                        t = (f32)(sv = xc + 0x14);
                        cwR = col2;
                        hudDrawTriangle(gMinimapF44, t,
                                        gMinimapF52, (f32)sv,
                                        gMinimapF48, (f32)(xc + 0x1a), &cwR);
                    }
                }
                t = (f32)(xl = xc - 4);
                e = (f32)(xr = xc + 4);
                a = (f32)(sv = xc);
                cwM = col2;
                hudDrawTriangle(gMinimapF28, t, gMinimapF28, e,
                                gMinimapF22, a, &cwM);
                cwB = col2;
                hudDrawTriangle(gMinimapF68, xl, gMinimapF68, xr,
                                gMinimapF74, xc, &cwB);
            }
        }
    }
    return 0;
}

u16 getMinimapY(void) { return lbl_803DD938; }

int titlescreen_getObjectTypeId(u8* obj);

ObjectDescriptor10WithPadding gTitleScreenObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)titlescreen_initialise,
        (ObjectDescriptorCallback)titlescreen_release,
        0,
        (ObjectDescriptorCallback)titlescreen_init,
        (ObjectDescriptorCallback)titlescreen_update,
        (ObjectDescriptorCallback)titlescreen_hitDetect,
        (ObjectDescriptorCallback)titlescreen_render,
        (ObjectDescriptorCallback)titlescreen_free,
        (ObjectDescriptorCallback)titlescreen_getObjectTypeId,
        titlescreen_getExtraSize,
    },
    0,
};

#pragma dont_inline on
void fn_80133818(void)
{
    f32 e;
    f32 d;
    f32 c;
    f32 b;
    f32 a;
    u8 i;

    i = 0;
    a = gMinimapFNeg15;
    b = gMinimapFNeg9_8;
    c = gMinimapZero;
    d = gMinimapFNeg40;
    e = gMinimapF0_05;
    for (; i < 2; i++)
    {
        lbl_803DBBC8[i] = (void*)Obj_SetupObject(Obj_AllocObjectSetup(32, 2010 + i), 4, -1, -1, 0);
        ((GameObject*)lbl_803DBBC8[i])->anim.localPosX = a;
        ((GameObject*)lbl_803DBBC8[i])->anim.localPosY = b;
        ((GameObject*)lbl_803DBBC8[i])->anim.localPosX = c;
        ((GameObject*)lbl_803DBBC8[i])->anim.localPosY = c;
        ((GameObject*)lbl_803DBBC8[i])->anim.localPosZ = d;
        ((GameObject*)lbl_803DBBC8[i])->anim.rotX = 2000;
        ((GameObject*)lbl_803DBBC8[i])->anim.rotY = 0;
        ((GameObject*)lbl_803DBBC8[i])->anim.rootMotionScale = e;
    }
}
#pragma dont_inline reset

void fn_80133718(void)
{
    u8 count;
    u8 i;
    int b;
    int* model;

    count = 2;
    viewFn_80129cbc(gMinimapF43, gMinimapF110, gMinimapF390);
    b = (gMinimapBlipPulse >> 3) & 1;
    if (b != 0)
    {
        if ((s8) * (u8*)((char*)lbl_803DBBC8[1] + 173) == 0)
        {
            Sfx_PlayFromObject(0, 1009);
        }
    }
    *(s8*)((char*)lbl_803DBBC8[1] + 173) = b;
    if ((u32)lbl_803DD934 == 0)
    {
        count = 1;
    }
    for (i = 0; i < count; i++)
    {
        objRender(0, 0, 0, 0, lbl_803DBBC8[i], 1);
        model = Obj_GetActiveModel(lbl_803DBBC8[i]);
        *(u16*)((char*)model + 24) = (u16)(*(u16*)((char*)model + 24) & ~0x8);
        *(u8*)((char*)lbl_803DBBC8[i] + 55) = 255;
    }
    viewFn_80129c74();
}

#pragma scheduling off
#pragma peephole off
void Minimap_release(void)
{
    u8 i;
    void** slots;
    void* null;
    if (minimapTexture != NULL) textureFree(minimapTexture);
    textureFree(lbl_803DD940);
    i = 0;
    slots = lbl_803DBBC8;
    null = NULL;
    while ((u32)i < 2)
    {
        if (slots[(u8)i] != NULL)
        {
            Obj_FreeObject(slots[(u8)i]);
            slots[(u8)i] = null;
        }
        i++;
    }
    minimapTexture = NULL;
    lbl_803DD940 = NULL;
}
#pragma peephole on

#pragma scheduling off
void Minimap_initialise(void)
{
    lbl_803DD940 = textureLoadAsset(0xBE5);
    lbl_803DD938 = 340;
}

#pragma scheduling on
void fn_80133934(void)
{
    if (minimapTexture != NULL)
    {
        textureFree(minimapTexture);
        minimapTexture = NULL;
        lbl_803DD92C = NULL;
    }
}

#pragma scheduling off
#pragma peephole off
u8 fn_801334E0(void)
{
    u32 act = 0;
    if (gMinimapViewMode == 2 && gMinimapEnabled != 0)
    {
        act = 1;
    }
    if ((u8)act == 0)
    {
        return act;
    }
    gMinimapAreaNameDelay = 5;
    return act;
}

volatile PPCWGPipe GXWGFifo : (0xCC008000);

void fn_8013351C(void)
{
    u32 col;
    u32 c2;
    f32 c0;
    f32 s0;
    f32 c1;
    f32 s1;
    f32 cc2;
    f32 s2;
    int y;

    col = gMinimapCompassColor;
    ((u8*)&col)[3] = gMinimapFadeAlpha;
    gMinimapCompassPhase = -(gMinimapBlipNearDist * timeDelta - gMinimapCompassPhase);
    if (gMinimapCompassPhase > *(f32*)&gMinimapF32768)
    {
        gMinimapCompassPhase = gMinimapCompassPhase - gMinimapF65536;
    }
    c0 = gMinimapF60 * mathSinf((gMinimapPi * gMinimapCompassPhase) / gMinimapF32768);
    s0 = gMinimapF60 * mathCosf((gMinimapPi * gMinimapCompassPhase) / gMinimapF32768);
    c1 = gMinimapTwo * mathSinf((gMinimapPi * (gMinimapCompassPhase + gMinimapF24576)) / gMinimapF32768);
    s1 = gMinimapTwo * mathCosf((gMinimapPi * (gMinimapCompassPhase + gMinimapF24576)) / gMinimapF32768);
    cc2 = gMinimapTwo * mathSinf((gMinimapPi * (gMinimapCompassPhase + gMinimapFNeg24576)) / gMinimapF32768);
    s2 = gMinimapTwo * mathCosf((gMinimapPi * (gMinimapCompassPhase + gMinimapFNeg24576)) / gMinimapF32768);
    y = lbl_803DD938 + 0x32;
    c2 = col;
    hudDrawTriangle(gMinimapF110 - c0, y - s0,
                    gMinimapF110 - c1, y - s1,
                    gMinimapF110 - cc2, y - s2, &c2);
}

void fn_8013396C(void)
{
    int player;
    int sfx;
    int held;
    int pressed;
    s16* slot;
    int a;
    s16 d;
    s16 v2;
    f32 t;
    f32 old;
    f32 pw;
    f32 dist = gMinimapFltMax;

    sfx = 0;
    player = (int)Obj_GetPlayerObject();
    if ((void*)player == NULL ||
        (*gCameraInterface)->getMode() == 0x44 ||
        Camera_GetViewportYOffset() != 0 ||
        (((GameObject*)player)->objectFlags & 0x1000) != 0 ||
        objIsCurModelNotZero(player) == 0 ||
        pauseMenuState != 0)
    {
        if (gMinimapZoomSfxActive != 0)
        {
            Sfx_StopFromObject(0, 0x3f0);
            gMinimapZoomSfxActive = 0;
        }
    }
    else
    {
        if (gMinimapAreaNameDelay != 0)
        {
            gMinimapAreaNameDelay = gMinimapAreaNameDelay - 1;
        }
        if ((*gGameUIInterface)->isEventReady(0xc8d) != 0)
        {
            gMinimapEnabled = 1 - gMinimapEnabled;
            switch (gMinimapEnabled)
            {
            case 0:
                sfx = 0x3ec;
                break;
            case 1:
                sfx = 0x3eb;
                break;
            }
            Sfx_PlayFromObject(0, sfx);
            sfx = 0;
        }
        if (gMinimapEnabled == 0 && lbl_803DD7BA == 0)
        {
            if (gMinimapZoomSfxActive != 0)
            {
                Sfx_StopFromObject(0, 0x3f0);
                gMinimapZoomSfxActive = 0;
            }
        }
        else
        {
            if (gMinimapRadarInited == 0)
            {
                gMinimapRadarInited = 1;
                fn_80133818();
            }
            held = (u16)getButtonsHeld(0);
            pressed = (u16)getButtonsJustPressed(0);
            if ((held & 0xc) == 0)
            {
                if ((pressed & 1) != 0)
                {
                    gMinimapViewMode -= 1;
                    sfx = 0x3ed;
                    if (gMinimapViewMode < 0)
                    {
                        gMinimapViewMode = 2;
                    }
                }
                else if ((pressed & 2) != 0)
                {
                    gMinimapViewMode += 1;
                    sfx = 0x3ed;
                    if (gMinimapViewMode > 2)
                    {
                        gMinimapViewMode = 0;
                    }
                }
            }
            if (lbl_803DD7BA != 0)
            {
                if (gMinimapSavedViewMode == -1)
                {
                    gMinimapSavedViewMode = gMinimapViewMode;
                }
                gMinimapViewMode = 2;
            }
            else
            {
                if (gMinimapSavedViewMode != -1)
                {
                    gMinimapViewMode = gMinimapSavedViewMode;
                    gMinimapSavedViewMode = -1;
                }
            }
            switch (gMinimapViewMode)
            {
            case 0:
                if ((held & 4) != 0)
                {
                    pw = powfCoreFast(gMinimapZoomInRate, timeDelta);
                    gMinimapZoomStep = gMinimapZoomStep * pw;
                }
                else if ((held & 8) != 0)
                {
                    pw = powfCoreFast(gMinimapZoomOutRate, timeDelta);
                    gMinimapZoomStep = gMinimapZoomStep * pw;
                }
                else
                {
                    gMinimapZoomStep = gMinimapOne;
                }
                t = (gMinimapZoomStep < gMinimapZoomStepMin) ? gMinimapZoomStepMin
                    : ((gMinimapZoomStep > gMinimapZoomStepMax) ? gMinimapZoomStepMax : gMinimapZoomStep);
                gMinimapZoomStep = t;
                old = gMinimapZoom;
                gMinimapZoom = old * t;
                t = (gMinimapZoom < gMinimapMinZoom) ? gMinimapMinZoom
                    : ((gMinimapZoom > gMinimapMaxZoom) ? gMinimapMaxZoom : gMinimapZoom);
                gMinimapZoom = t;
                if (t != old)
                {
                    if (gMinimapZoomSfxActive == 0)
                    {
                        Sfx_PlayFromObject(0, 0x3f0);
                        gMinimapZoomSfxActive = 1;
                    }
                }
                else
                {
                    if (gMinimapZoomSfxActive != 0)
                    {
                        Sfx_StopFromObject(0, 0x3f0);
                        gMinimapZoomSfxActive = 0;
                    }
                }
                break;
            case 1:
                if (gMinimapZoomSfxActive != 0)
                {
                    Sfx_StopFromObject(0, 0x3f0);
                    gMinimapZoomSfxActive = 0;
                }
                lbl_803DD934 = ObjGroup_FindNearestObject(0x4f, player, &dist);
                if ((void*)lbl_803DD934 != NULL)
                {
                    if (dist < gMinimapBlipNearDist)
                    {
                        gMinimapBlipPulse += 1;
                        if (dist < gMinimapBlipVeryNearDist)
                        {
                            gMinimapBlipPulse += 1;
                        }
                    }
                    else
                    {
                        gMinimapBlipPulse = 0;
                    }
                    slot = Camera_GetCurrentViewSlot();
                    a = getAngle(((GameObject*)lbl_803DD934)->anim.localPosX - ((GameObject*)player)->anim.localPosX,
                                 ((GameObject*)lbl_803DD934)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ);
                    a = *slot + a;
                    d = a - (u16)((GameObject*)lbl_803DBBC8[1])->anim.rotZ;
                    if (d > 0x8000)
                    {
                        d = (d - 0x10000) + 1;
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    *(s16*)((char*)lbl_803DBBC8[1] + 4) = *(s16*)(int)((char*)lbl_803DBBC8[1] + 4) + d / 5;
                }
                break;
            case 2:
                if (gMinimapZoomSfxActive != 0)
                {
                    Sfx_StopFromObject(0, 0x3f0);
                    gMinimapZoomSfxActive = 0;
                }
                v2 = lbl_803DBA6E;
                if (v2 != gMinimapPrevAreaNameId)
                {
                    switch (v2)
                    {
                    case -1:
                        sfx = 0x3ef;
                        break;
                    default:
                        sfx = 0x3ee;
                        break;
                    }
                }
                gMinimapPrevAreaNameId = v2;
                break;
            }
            if ((u16)sfx != 0)
            {
                Sfx_PlayFromObject(0, sfx);
            }
        }
    }
}
