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

extern int coordsToMapCell(f32 x, f32 z);
extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern int Camera_GetViewportYOffset(void);
extern int objIsCurModelNotZero(int obj);
extern void* gameTextGetBox(int boxId);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
extern void hudDrawTriangle(f32 x0, f32 y0, f32 x1, f32 y1, f32 x2, f32 y2, u32* color);
extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32* color);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int scale, u32 w, u32 h, u32 u, u32 v);
extern void drawHudBox(int id, int x, int y, int w, int alpha, int p6);
extern void gameTextSetCursor(int a, int b, int c);
extern void gameTextResetCursor(int n);
extern int gameTextGetCharset(void);
extern void gameTextSetCharset(int a, int b);

extern u8 lbl_803DBBB0;
extern u8 lbl_803DD7BA;
extern s16 lbl_803DD7A2;
extern s16 lbl_803DBA6E;
extern u8 lbl_803DD928;
extern int lbl_803DD934;
extern u8 pauseMenuState;
extern u8 lbl_803DD75B;
extern s16 lbl_803DD930;
extern s16 lbl_803DD932;
extern u32 lbl_803DD938;
extern void* lbl_803DD92C;
extern void* minimapTexture;
extern void* lbl_803DD940;
extern u8 lbl_803DD946;
extern u8 lbl_803DD947;
extern s16 lbl_803DD948;
extern s16 lbl_803DD94A;
extern s16 lbl_803DBBD0;
extern s16 lbl_803DBBD2;
extern s8 lbl_803DD95C;
extern s8 lbl_803DD944;
extern int lbl_803DBBC0;
extern int lbl_803DBBC4;
extern f32 lbl_803DBBB4;
extern f32 lbl_803DBBB8;
extern f32 lbl_803DBBBC;
extern f32 lbl_803DBBEC;
extern f32 lbl_803DD950;
extern f32 lbl_803DD954;
extern f32 lbl_803DD958;
extern u8 framesThisStep;
extern u32 lbl_803E2204;
extern f32 lbl_803E2208;
extern f32 lbl_803E2210;
extern f32 lbl_803E2214;
extern f32 lbl_803E2218;
extern f32 lbl_803E221C;
extern f32 lbl_803E2220;
extern f32 lbl_803E2224;
extern f32 lbl_803E2228;
extern f32 lbl_803E222C;
extern f32 lbl_803E2230;
extern f32 lbl_803E2234;
extern f32 lbl_803E2238;
extern f32 lbl_803E223C;
extern f32 lbl_803E2240;
extern f32 lbl_803E2244;
extern f32 lbl_803E2248;
extern f32 lbl_803E224C;

#pragma scheduling off
#pragma peephole off
extern void titlescreen_free(u8 * obj);
extern void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void titlescreen_update(u8 * obj);
extern void titlescreen_init(u8 * obj, u8 * p);
extern void titlescreen_release(void);
extern void titlescreen_initialise(void);
extern void* lbl_803DBBC8[2];
extern void Obj_FreeObject(void*);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int obj, int b, int c, int d, int e);
extern f32 lbl_803E2284;
extern f32 lbl_803E2288;
extern f32 lbl_803E228C;
extern f32 lbl_803E2290;
extern void viewFn_80129cbc(f32 a, f32 b, f32 c);
extern void viewFn_80129c74(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objRender(int a, int b, int c, int d, void* obj, int f);
extern int* Obj_GetActiveModel(void* obj);
extern u8 lbl_803DD92A;
extern f32 lbl_803E2278;
extern f32 lbl_803E227C;
extern f32 lbl_803E2280;
extern f32 timeDelta;
extern void Sfx_StopFromObject(int obj, int id);
extern u32 lbl_803E2200;
extern f32 lbl_803DD94C;
extern f32 lbl_803E2260;
extern f32 lbl_803E2264;
extern f32 lbl_803E2268;
extern f32 lbl_803E226C;
extern f32 lbl_803E2270;
extern f32 lbl_803E2274;
extern int getButtonsHeld(int p);
extern int getButtonsJustPressed(int p);
extern f32 powfCoreFast(f32 base, f32 exp);
extern s16* Camera_GetCurrentViewSlot(void);
extern int getAngle(f32 dx, f32 dz);
extern u8 lbl_803DD945;
extern u8 lbl_803DD929;
extern s8 lbl_803DBBB1;
extern int lbl_803DBBE8;
extern f32 lbl_803DBBD4;
extern f32 lbl_803DBBD8;
extern f32 lbl_803DBBDC;
extern f32 lbl_803DBBE0;
extern f32 lbl_803DBBE4;
extern f32 lbl_803E2294;
extern f32 lbl_803E2298;
extern f32 lbl_803E229C;

int Minimap_update(void)
{
    u8* player;
    int marker;
    u8 i, k, j, found, cell;
    MinimapRow* rows;
    MinimapRow* row;
    MinimapRow* r2;
    int yi;
    int v;
    s16 m;
    s16 sv, sw;
    int n;
    int w;
    u16* box;
    u16 hw;
    int cs;
    u32 texW, texH;
    int boxW, boxH;
    f32 fx, fz;
    f32 ox, oy;
    f32 xrel, yrel;
    f32 panx, pany;
    f32 t, e, a, b;
    f32 uq, vq, frac;
    u32 u, vv;
    f32 cx, cy;
    f32 c1, s1, c2, s2, c3, s3;
    f32 fv;
    int xc, xl, xr;
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
    ox = 0.0f;
    oy = 0.0f;
    col = lbl_803E2204;
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
                lbl_803DD95C = 1;
            }
            else
            {
                fx = ((GameObject*)player)->anim.worldPosX;
                fz = ((GameObject*)player)->anim.worldPosZ;
                lbl_803DD95C = 0;
            }
            yi = (int)((GameObject*)player)->anim.worldPosY;
            for (; k < gMinimapCellTable[i].count; k++)
            {
                row = &rows[k];
                if (fx >= row->x0 && fx < row->x1 &&
                    fz >= row->z0 && fz < row->z1 &&
                    yi >= row->y0 && yi < row->y1 &&
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
                        lbl_803DD948 = -0x8000;
                        lbl_803DD94A = -0x8000;
                        lbl_803DBBD0 = 0x7fff;
                        lbl_803DBBD2 = 0x7fff;
                        for (; j < gMinimapCellTable[i].count; j++)
                        {
                            r2 = &rows[j];
                            if (marker == r2->mapId)
                            {
                                m = r2->x0;
                                lbl_803DBBD0 = (m >= lbl_803DBBD0) ? lbl_803DBBD0 : m;
                                m = r2->x1;
                                lbl_803DD948 = (m <= lbl_803DD948) ? lbl_803DD948 : m;
                                m = r2->z0;
                                lbl_803DBBD2 = (m >= lbl_803DBBD2) ? lbl_803DBBD2 : m;
                                m = r2->z1;
                                lbl_803DD94A = (m <= lbl_803DD94A) ? lbl_803DD94A : m;
                            }
                        }
                        lbl_803DD946 = rows[k].texU;
                        lbl_803DD947 = rows[k].texV;
                    }
                    break;
                }
            }
        }
        if ((lbl_803DBBB0 == 0 && lbl_803DD7BA == 0) || GameBit_Get(0x58d) != 0)
        {
            marker = 0;
        }
        if ((*gCameraInterface)->getMode() == 0x44 ||
            (lbl_803DBBB0 == 0 && lbl_803DD7BA == 0) ||
            Camera_GetViewportYOffset() != 0 ||
            (((GameObject*)player)->objectFlags & 0x1000) != 0 ||
            objIsCurModelNotZero((int)player) == 0 ||
            pauseMenuState != 0 || lbl_803DD75B != 0)
        {
            marker = 0;
            lbl_803DD930 -= 0x20;
            n = lbl_803DD930;
            if (n < 0) n = 0;
            else if (n > 0xff) n = 0xff;
            lbl_803DD930 = n;
            lbl_803DBBC0 -= 10;
            n = lbl_803DBBC0;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            lbl_803DBBC0 = n;
            lbl_803DBBC4 -= 10;
            n = lbl_803DBBC4;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            lbl_803DBBC4 = n;
        }
        else
        {
            lbl_803DBBC4 += 10;
            n = lbl_803DBBC4;
            if (n < 0) n = 0;
            else if (n > 100) n = 100;
            lbl_803DBBC4 = n;
            lbl_803DD930 += 0x20;
            n = lbl_803DD930;
            if (n < 0) n = 0;
            else if (n > 0xff) n = 0xff;
            lbl_803DD930 = n;
        }
        if ((int)lbl_803DD92C == marker)
        {
            lbl_803DD932 += 0x20;
            n = lbl_803DD932;
            if (n < 0)
            {
                n = 0;
            }
            else
            {
                n = (s16)((n > lbl_803DD930) ? lbl_803DD930 : n);
            }
            lbl_803DD932 = n;
        }
        else
        {
            lbl_803DD932 -= 0x20;
            if (lbl_803DD932 < 0)
            {
                lbl_803DD932 = 0;
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
        if (lbl_803DD930 != 0)
        {
            box = gameTextGetBox(0x83);
            if (lbl_803DD944 == 2 && lbl_803DD7A2 != 0 && lbl_803DBA6E > -1)
            {
                w = 200;
            }
            else
            {
                w = 0x78;
            }
            if (lbl_803DBBC0 < w)
            {
                lbl_803DBBC0 += framesThisStep * 8;
                lbl_803DBBC0 = (lbl_803DBBC0 < w) ? lbl_803DBBC0 : w;
            }
            else
            {
                lbl_803DBBC0 -= framesThisStep * 8;
                lbl_803DBBC0 = (lbl_803DBBC0 > w) ? lbl_803DBBC0 : w;
            }
            box[4] = (u16)(lbl_803DBBC0 - 8);
            lbl_803DD938 = 0x1b8 - lbl_803DBBC4;
            ((s16*)box)[0xb] = lbl_803DD938;
            drawHudBox(0x32, lbl_803DD938, lbl_803DBBC0, lbl_803DBBC4,
                       lbl_803DD930 & 0xff, 1);
            GXSetScissor(0x32, lbl_803DD938, lbl_803DBBC0, lbl_803DBBC4);
            switch (lbl_803DD944)
            {
            case 0:
                if (minimapTexture != NULL)
                {
                    texW = ((Texture*)minimapTexture)->width;
                    texH = ((Texture*)minimapTexture)->height;
                    lbl_803DBBEC = texW / (f32)(lbl_803DD948 - lbl_803DBBD0);
                    boxW = lbl_803DBBC0;
                    a = boxW / texW;
                    boxH = lbl_803DBBC4;
                    b = boxH / texH;
                    a = (a < b) ? a : b;
                    a = (a < lbl_803DBBBC) ? a : lbl_803DBBBC;
                    lbl_803DBBB8 = a;
                    if (lbl_803DD95C != 0)
                    {
                        xrel = -((GameObject*)player)->anim.worldPosZ + lbl_803DD948;
                        yrel = ((GameObject*)player)->anim.worldPosX - lbl_803DBBD2;
                    }
                    else
                    {
                        xrel = -((GameObject*)player)->anim.worldPosX + lbl_803DD948;
                        yrel = -((GameObject*)player)->anim.worldPosZ + lbl_803DD94A;
                    }
                    e = boxW - texW * lbl_803DBBB4;
                    e = e * 0.5f;
                    t = 0.0f;
                    t = (t > e) ? t : e;
                    panx = -t;
                    e = boxH - texH * lbl_803DBBB4;
                    e = e * 0.5f;
                    t = 0.0f;
                    t = (t > e) ? t : e;
                    pany = -t;
                    t = 0.0f;
                    if (t == panx)
                    {
                        a = lbl_803DBBB4 * (xrel * lbl_803DBBEC) - (f32)(boxW / 2);
                        t = (t > a) ? t : a;
                        b = texW * lbl_803DBBB4 - boxW;
                        t = (t < b) ? t : b;
                        ox = t;
                    }
                    t = *(f32*)&lbl_803E2208;
                    if (t == pany)
                    {
                        a = lbl_803DBBB4 * (yrel * lbl_803DBBEC) - (f32)(boxH / 2);
                        t = (t > a) ? t : a;
                        b = texH * lbl_803DBBB4 - boxH;
                        t = (t < b) ? t : b;
                        oy = t;
                    }
                    uq = ox / lbl_803DBBB4;
                    u = uq;
                    frac = lbl_803DBBB4 * (uq - u);
                    vq = oy / lbl_803DBBB4;
                    vv = vq;
                    ((u8*)&col)[3] = lbl_803DD932;
                    ((u8*)&col)[0] = 0x20;
                    ((u8*)&col)[1] = 0x4d;
                    ((u8*)&col)[2] = 0x84;
                    cwRect = col;
                    hudDrawRect(0x32, lbl_803DD938, boxW + 0x32, lbl_803DD938 + boxH, &cwRect);
                    fv = lbl_803DBBB4 * (vq - vv);
                    drawPartialTexture(minimapTexture,
                                       (lbl_803E2210 - panx) - frac,
                                       ((f32)(int)lbl_803DD938 - pany) - fv,
                                       lbl_803DD932,
                                       (int)(lbl_803E2214 * *(f32*)&lbl_803DBBB4),
                                       texW - u, texH - vv, u, vv);
                    cx = 0.5f +
                        ((lbl_803DBBB4 * (xrel * lbl_803DBBEC) + lbl_803E2210) - ox - panx);
                    cy = 0.5f +
                        ((lbl_803DBBB4 * (yrel * lbl_803DBBEC) + (f32)(int)lbl_803DD938) - oy - pany);
                    ((u8*)&col)[3] = lbl_803DD932;
                    ((u8*)&col)[0] = 0;
                    ((u8*)&col)[1] = 0;
                    ((u8*)&col)[2] = 0;
                    lbl_803DD958 = lbl_803E2218;
                    fv = lbl_803E221C;
                    lbl_803DD954 = fv;
                    lbl_803DD950 = fv;
                    c1 = lbl_803DD958 * mathSinf(lbl_803E2220 * (f32)((GameObject*)player)->anim.rotX / lbl_803E2224);
                    s1 = lbl_803DD958 * mathCosf(lbl_803E2220 * (f32)((GameObject*)player)->anim.rotX / lbl_803E2224);
                    c2 = lbl_803DD954 *
                        mathSinf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / lbl_803E2224);
                    s2 = lbl_803DD954 *
                        mathCosf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / lbl_803E2224);
                    c3 = lbl_803DD950 *
                        mathSinf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / lbl_803E2224);
                    s3 = lbl_803DD950 *
                        mathCosf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / lbl_803E2224);
                    cwTri1 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri1);
                    ((u8*)&col)[3] = lbl_803DD932;
                    ((u8*)&col)[0] = 0xff;
                    ((u8*)&col)[1] = 0xff;
                    ((u8*)&col)[2] = 0;
                    c1 = lbl_803E2228 * mathSinf(lbl_803E2220 * (f32)((GameObject*)player)->anim.rotX / lbl_803E2224);
                    s1 = lbl_803E2228 * mathCosf(lbl_803E2220 * (f32)((GameObject*)player)->anim.rotX / lbl_803E2224);
                    c2 = lbl_803E222C *
                        mathSinf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / lbl_803E2224);
                    s2 = lbl_803E222C *
                        mathCosf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX + 0x6000) / lbl_803E2224);
                    c3 = lbl_803E222C *
                        mathSinf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / lbl_803E2224);
                    s3 = lbl_803E222C *
                        mathCosf(lbl_803E2220 * (f32)(((GameObject*)player)->anim.rotX - 0x6000) / lbl_803E2224);
                    cwTri2 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri2);
                }
                else
                {
                    gameTextSetCursor(box[1], box[5], 1);
                    gameTextResetCursor(1);
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw >= box[0]) ? box[0] : hw;
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
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
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw >= box[0]) ? box[0] : hw;
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
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
                    if (lbl_803DD928 == 0)
                    {
                        gameTextSetCursor(box[1], box[5], 1);
                        gameTextResetCursor(1);
                        box[4] = lbl_803DBBC0;
                        box[5] = lbl_803DBBC4;
                        gameTextSetCursor(box[1], box[5], 2);
                        gameTextSetColor(0, 0xff, 0, lbl_803DD7A2 & 0xff);
                        gameTextShow(lbl_803DBA6E + 10000);
                        gameTextResetCursor(2);
                    }
                }
                else if (lbl_803DBBB0 != 0)
                {
                    fn_8013351C();
                    gameTextSetCursor(box[1], box[5], 1);
                    gameTextResetCursor(1);
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw >= box[0]) ? box[0] : hw;
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
                    cs = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x45a);
                    gameTextSetCharset(cs, 3);
                    gameTextResetCursor(2);
                }
                break;
            }
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawTexture(lbl_803DD940, lbl_803E2230, (f32)(int)(lbl_803DD938 - 0x14),
                        lbl_803DD930 & 0xff, 0x100);
            if (lbl_803DD930 != 0)
            {
                ((u8*)&col2)[3] = lbl_803DD932;
                ((u8*)&col2)[0] = 0xff;
                ((u8*)&col2)[1] = 0xff;
                ((u8*)&col2)[2] = 0;
                xc = (s16)(lbl_803DD938 - 4);
                if (lbl_803DD944 == 0 && minimapTexture != NULL)
                {
                    if (lbl_803DBBB4 < lbl_803DBBBC)
                    {
                        cwL = col2;
                        hudDrawTriangle(lbl_803E2234, (f32)(xc - 0x14),
                                        lbl_803E2238, (f32)(xc - 0x14),
                                        lbl_803E223C, (f32)(xc - 0x1a), &cwL);
                    }
                    if (lbl_803DBBB4 > lbl_803DBBB8)
                    {
                        cwR = col2;
                        hudDrawTriangle(lbl_803E2234, (f32)(xc + 0x14),
                                        lbl_803E2238, (f32)(xc + 0x14),
                                        lbl_803E223C, (f32)(xc + 0x1a), &cwR);
                    }
                }
                xl = xc - 4;
                xr = xc + 4;
                cwM = col2;
                hudDrawTriangle(lbl_803E2240, xl, lbl_803E2240, xr,
                                lbl_803E2244, xc, &cwM);
                cwB = col2;
                hudDrawTriangle(lbl_803E2248, xl, lbl_803E2248, xr,
                                lbl_803E224C, xc, &cwB);
            }
        }
    }
    return 0;
}

u16 getMinimapY(void) { return lbl_803DD938; }

int titlescreen_getExtraSize(void);
void titlescreen_hitDetect(void);
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
    a = lbl_803E2284;
    b = lbl_803E2288;
    c = lbl_803E2208;
    d = lbl_803E228C;
    e = lbl_803E2290;
    for (; i < 2; i++)
    {
        lbl_803DBBC8[i] = (void*)Obj_SetupObject(Obj_AllocObjectSetup(32, 2010 + i), 4, -1, -1, 0);
        *(f32*)((char*)lbl_803DBBC8[i] + 0xc) = a;
        *(f32*)((char*)lbl_803DBBC8[i] + 0x10) = b;
        *(f32*)((char*)lbl_803DBBC8[i] + 0xc) = c;
        *(f32*)((char*)lbl_803DBBC8[i] + 0x10) = c;
        *(f32*)((char*)lbl_803DBBC8[i] + 0x14) = d;
        *(u16*)lbl_803DBBC8[i] = 2000;
        *(u16*)((char*)lbl_803DBBC8[i] + 2) = 0;
        *(f32*)((char*)lbl_803DBBC8[i] + 8) = e;
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
    viewFn_80129cbc(lbl_803E227C, lbl_803E2278, lbl_803E2280);
    b = (lbl_803DD92A >> 3) & 1;
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
        if (slots[i] != NULL)
        {
            Obj_FreeObject(slots[i]);
            slots[i] = null;
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
    if (lbl_803DD944 == 2 && lbl_803DBBB0 != 0)
    {
        act = 1;
    }
    act = act;
    if (act == 0) return act;
    lbl_803DD928 = 5;
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

    col = lbl_803E2200;
    ((u8*)&col)[3] = lbl_803DD930;
    lbl_803DD94C = -(lbl_803E2260 * timeDelta - lbl_803DD94C);
    if (lbl_803DD94C > *(f32*)&lbl_803E2224)
    {
        lbl_803DD94C = lbl_803DD94C - lbl_803E2264;
    }
    c0 = lbl_803E2268 * mathSinf((lbl_803E2220 * lbl_803DD94C) / lbl_803E2224);
    s0 = lbl_803E2268 * mathCosf((lbl_803E2220 * lbl_803DD94C) / lbl_803E2224);
    c1 = lbl_803E226C * mathSinf((lbl_803E2220 * (lbl_803DD94C + lbl_803E2270)) / lbl_803E2224);
    s1 = lbl_803E226C * mathCosf((lbl_803E2220 * (lbl_803DD94C + lbl_803E2270)) / lbl_803E2224);
    cc2 = lbl_803E226C * mathSinf((lbl_803E2220 * (lbl_803DD94C + lbl_803E2274)) / lbl_803E2224);
    s2 = lbl_803E226C * mathCosf((lbl_803E2220 * (lbl_803DD94C + lbl_803E2274)) / lbl_803E2224);
    y = lbl_803DD938 + 0x32;
    c2 = col;
    hudDrawTriangle(lbl_803E2278 - c0, y - s0,
                    lbl_803E2278 - c1, y - s1,
                    lbl_803E2278 - cc2, y - s2, &c2);
}

extern int ObjGroup_FindNearestObject(int type, int obj, f32* distOut);

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
    f32 dist = lbl_803E2294;

    sfx = 0;
    player = (int)Obj_GetPlayerObject();
    if ((void*)player == NULL ||
        (*gCameraInterface)->getMode() == 0x44 ||
        Camera_GetViewportYOffset() != 0 ||
        (((GameObject*)player)->objectFlags & 0x1000) != 0 ||
        objIsCurModelNotZero(player) == 0 ||
        pauseMenuState != 0)
    {
        if (lbl_803DD945 != 0)
        {
            Sfx_StopFromObject(0, 0x3f0);
            lbl_803DD945 = 0;
        }
    }
    else
    {
        if (lbl_803DD928 != 0)
        {
            lbl_803DD928 = lbl_803DD928 - 1;
        }
        if ((*gGameUIInterface)->isEventReady(0xc8d) != 0)
        {
            lbl_803DBBB0 = 1 - lbl_803DBBB0;
            switch (lbl_803DBBB0)
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
        if (lbl_803DBBB0 == 0 && lbl_803DD7BA == 0)
        {
            if (lbl_803DD945 != 0)
            {
                Sfx_StopFromObject(0, 0x3f0);
                lbl_803DD945 = 0;
            }
        }
        else
        {
            if (lbl_803DD929 == 0)
            {
                lbl_803DD929 = 1;
                fn_80133818();
            }
            held = getButtonsHeld(0);
            pressed = getButtonsJustPressed(0);
            if ((held & 0xc) == 0)
            {
                if ((pressed & 1) != 0)
                {
                    lbl_803DD944 -= 1;
                    sfx = 0x3ed;
                    if (lbl_803DD944 < 0)
                    {
                        lbl_803DD944 = 2;
                    }
                }
                else if ((pressed & 2) != 0)
                {
                    lbl_803DD944 += 1;
                    sfx = 0x3ed;
                    if (lbl_803DD944 > 2)
                    {
                        lbl_803DD944 = 0;
                    }
                }
            }
            if (lbl_803DD7BA != 0)
            {
                if (lbl_803DBBB1 == -1)
                {
                    lbl_803DBBB1 = lbl_803DD944;
                }
                lbl_803DD944 = 2;
            }
            else
            {
                if (lbl_803DBBB1 != -1)
                {
                    lbl_803DD944 = lbl_803DBBB1;
                    lbl_803DBBB1 = -1;
                }
            }
            switch (lbl_803DD944)
            {
            case 0:
                if ((held & 4) != 0)
                {
                    pw = powfCoreFast(lbl_803DBBD4, timeDelta);
                    lbl_803DBBE4 = lbl_803DBBE4 * pw;
                }
                else if ((held & 8) != 0)
                {
                    pw = powfCoreFast(lbl_803DBBD8, timeDelta);
                    lbl_803DBBE4 = lbl_803DBBE4 * pw;
                }
                else
                {
                    lbl_803DBBE4 = lbl_803E2298;
                }
                t = (lbl_803DBBE4 < lbl_803DBBDC) ? lbl_803DBBDC
                    : ((lbl_803DBBE4 > lbl_803DBBE0) ? lbl_803DBBE0 : lbl_803DBBE4);
                lbl_803DBBE4 = t;
                old = lbl_803DBBB4;
                lbl_803DBBB4 = old * t;
                t = (lbl_803DBBB4 < lbl_803DBBB8) ? lbl_803DBBB8
                    : ((lbl_803DBBB4 > lbl_803DBBBC) ? lbl_803DBBBC : lbl_803DBBB4);
                lbl_803DBBB4 = t;
                if (t != old)
                {
                    if (lbl_803DD945 == 0)
                    {
                        Sfx_PlayFromObject(0, 0x3f0);
                        lbl_803DD945 = 1;
                    }
                }
                else
                {
                    if (lbl_803DD945 != 0)
                    {
                        Sfx_StopFromObject(0, 0x3f0);
                        lbl_803DD945 = 0;
                    }
                }
                break;
            case 1:
                if (lbl_803DD945 != 0)
                {
                    Sfx_StopFromObject(0, 0x3f0);
                    lbl_803DD945 = 0;
                }
                lbl_803DD934 = ObjGroup_FindNearestObject(0x4f, player, &dist);
                if ((void*)lbl_803DD934 != NULL)
                {
                    if (dist < lbl_803E2260)
                    {
                        lbl_803DD92A += 1;
                        if (dist < lbl_803E229C)
                        {
                            lbl_803DD92A += 1;
                        }
                    }
                    else
                    {
                        lbl_803DD92A = 0;
                    }
                    slot = Camera_GetCurrentViewSlot();
                    a = getAngle(*(f32*)(lbl_803DD934 + 0xc) - ((GameObject*)player)->anim.localPosX,
                                 *(f32*)(lbl_803DD934 + 0x14) - ((GameObject*)player)->anim.localPosZ);
                    d = *slot + a - (u16) * (s16*)((char*)lbl_803DBBC8[1] + 4);
                    if (d > 0x8000)
                    {
                        d -= 0xffff;
                    }
                    if (d < -0x8000)
                    {
                        d += 0xffff;
                    }
                    *(s16*)((char*)lbl_803DBBC8[1] + 4) = *(s16*)((char*)lbl_803DBBC8[1] + 4) + d / 5;
                }
                break;
            case 2:
                if (lbl_803DD945 != 0)
                {
                    Sfx_StopFromObject(0, 0x3f0);
                    lbl_803DD945 = 0;
                }
                v2 = lbl_803DBA6E;
                if (v2 != lbl_803DBBE8)
                {
                    if (v2 == -1)
                    {
                        sfx = 0x3ef;
                    }
                    else
                    {
                        sfx = 0x3ee;
                    }
                }
                lbl_803DBBE8 = v2;
                break;
            }
            if ((u16)sfx != 0)
            {
                Sfx_PlayFromObject(0, sfx);
            }
        }
    }
}
