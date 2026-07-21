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
 * texture buffers (minimapTexture, the compass at gMinimapCompassTexture) and the
 * 2-slot live-objects table at gMinimapBlipObjects.
 */
#include "main/texture.h"
#include "track/intersect_hud_api.h"
#include "main/gametext_box_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/objprint_render_api.h"
#include "main/gamebits.h"
#include "dolphin/gx/GXCull.h"
#include "main/pad.h"
#include "main/camera.h"
#include "main/obj_group.h"
#include "main/lightmap_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/minimap_api.h"
#include "main/textrender_api.h"
#include "main/pause_menu_api.h"
#include "main/dll/dll_003F_dll3f.h"

u8 gMinimapEnabled = 1;
s8 gMinimapSavedViewMode = -1;
f32 gMinimapZoom = 1.0f;
f32 gMinimapMinZoom = 0.3f;
f32 gMinimapMaxZoom = 2.0f;
int gMinimapBoxWidth = 120;
int gMinimapBoxHeight = 100;
GameObject* gMinimapBlipObjects[2] = {0};
s16 gMinimapRegionMinX = 0x7FFF;
s16 gMinimapRegionMinZ = 0x7FFF;
f32 gMinimapZoomInRate = 0.995f;
f32 gMinimapZoomOutRate = 1.001f;
f32 gMinimapZoomStepMin = 0.952f;
f32 gMinimapZoomStepMax = 1.05f;
f32 gMinimapZoomStep = 1.0f;
int gMinimapPrevAreaNameId = -1;
f32 gMinimapWorldToTexScale = 0.08f;

#define CAMMODE_VIEWFINDER 0x44 /* dll_0044_cameramodeviewfinder */

/* group owned by another DLL, queried here */
#define FUELCELL_OBJGROUP 0x4f /* DLL 0x123 fuelcell */

#define MINIMAP_OBJFLAG_PARENT_SLACK 0x1000

/* compass texture asset (loaded into gMinimapCompassTexture; see file header). */
#define MINIMAP_TEXTURE_COMPASS 0xBE5

/* base of the 2-object run spawned into gMinimapBlipObjects; both 0x7DA and 0x7DB are
   "CommandMenu" in the retail OBJECTS.bin, so only the run base is named here. */
#define MINIMAP_COMMAND_MENU_OBJ_BASE 2010

/* gMinimapViewMode selector (see file header): the three HUD view modes. */
#define MINIMAP_VIEW_MODE_MAP       0
#define MINIMAP_VIEW_MODE_RADAR     1
#define MINIMAP_VIEW_MODE_AREA_NAME 2

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

typedef union MinimapColor
{
    u32 value;
    GXColor channels;
} MinimapColor;

typedef struct MinimapTextBox
{
    u16 width;
    u16 cursorX;
    u8 pad04[4];
    u16 clipWidth;
    u16 cursorY;
    u8 pad0C[10];
    s16 y;
} MinimapTextBox;

extern MinimapRow lbl_8031C328[];
extern MinimapRow lbl_8031C33C[];
extern MinimapRow lbl_8031C350[];
extern MinimapRow lbl_8031C364[];
extern MinimapRow lbl_8031C378[];
extern MinimapRow lbl_8031C38C[];
extern MinimapRow lbl_8031C3A0[];
extern MinimapRow lbl_8031C3B4[];
extern MinimapRow lbl_8031C3C8[];
extern MinimapRow lbl_8031C3DC[];
extern MinimapRow lbl_8031C3F0[];
extern MinimapRow lbl_8031C404[];
extern MinimapRow lbl_8031C418[];
extern MinimapRow lbl_8031C440[];
extern MinimapRow lbl_8031C454[];
extern MinimapRow lbl_8031C468[];
extern MinimapRow lbl_8031C47C[];
extern MinimapRow lbl_8031C490[];
extern MinimapRow lbl_8031C4A4[];
extern MinimapRow lbl_8031C4B8[];
extern MinimapRow lbl_8031C4CC[];
extern MinimapRow lbl_8031C4E0[];
extern MinimapRow lbl_8031C4F4[];

MinimapMapEntry gMinimapCellTable[25] = {
    {lbl_8031C328, 0x059E, 0x13, 1}, {lbl_8031C33C, 0x059E, 0x1B, 1}, {lbl_8031C350, 0x05A2, 0x0E, 1},
    {lbl_8031C364, 0x05A2, 0x47, 1}, {lbl_8031C378, 0x05A3, 0x07, 1}, {lbl_8031C38C, 0x05A3, 0x43, 1},
    {lbl_8031C3A0, 0x0835, 0x12, 1}, {lbl_8031C3B4, 0x0835, 0x45, 1}, {lbl_8031C3C8, 0x082E, 0x0D, 1},
    {lbl_8031C3DC, 0x05A1, 0x0C, 1}, {lbl_8031C3DC, 0x05A1, 0x10, 1}, {lbl_8031C3DC, 0x05A1, 0x0F, 1},
    {lbl_8031C3F0, 0x05A1, 0x2B, 1}, {lbl_8031C404, 0x07E5, 0x0B, 1}, {lbl_8031C418, 0x059D, 0x04, 2},
    {lbl_8031C440, 0x059D, 0x46, 1}, {lbl_8031C454, 0x05A3, 0x08, 1}, {lbl_8031C468, 0x05A0, 0x0A, 1},
    {lbl_8031C47C, 0x05A0, 0x38, 1}, {lbl_8031C490, 0x07E9, 0x32, 1}, {lbl_8031C4A4, 0x07E9, 0x15, 1},
    {lbl_8031C4B8, 0x07E9, 0x49, 1}, {lbl_8031C4CC, 0x082F, 0x1D, 1}, {lbl_8031C4E0, 0x082F, 0x48, 1},
    {lbl_8031C4F4, 0x07DD, 0x02, 1},
};

void Minimap_drawCompassBlip(void);
void Minimap_setupCompassBlip(void);
void Minimap_drawCompassNeedle(void);

extern u8 lbl_803DD7BA;
extern s16 lbl_803DD7A2;
extern s16 lbl_803DBA6E;
s8 gMinimapAxisSwap;
f32 gMinimapArrowScale0;
f32 gMinimapArrowScale1;
f32 gMinimapArrowScale2;
f32 gMinimapCompassPhase;
s16 gMinimapRegionMaxZ;
s16 gMinimapRegionMaxX;
u8 gMinimapTexV;
u8 gMinimapTexU;
u8 gMinimapZoomSfxActive;
s8 gMinimapViewMode;
Texture* gMinimapCompassTexture;
Texture* minimapTexture;
u32 gMinimapBoxY;
GameObject* gMinimapRadarTarget;
s16 gMinimapContentAlpha;
s16 gMinimapFadeAlpha;
int gMinimapLoadedMapId;
u8 gMinimapBlipPulse;
u8 gMinimapRadarInited;
u8 gMinimapAreaNameDelay;
extern u8 lbl_803DD75B;
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

extern f32 gMinimapFNeg15;
extern f32 gMinimapFNeg9_8;
extern f32 gMinimapFNeg40;
extern f32 gMinimapF0_05;

extern f32 gMinimapF110;
extern f32 gMinimapF43;
extern f32 gMinimapF390;
extern u32 gMinimapCompassColor;
extern f32 gMinimapBlipNearDist;
extern f32 gMinimapF65536;
extern f32 gMinimapF60;
extern f32 gMinimapTwo;
extern f32 gMinimapF24576;
extern f32 gMinimapFNeg24576;
extern f32 gMinimapFltMax;
extern f32 gMinimapOne;
extern f32 gMinimapBlipVeryNearDist;

int Minimap_update(void)
{
    u32 mapTileV, mapTileU;
    int mapTextureId;
    u8 found;
    u8 cell;
    int playerWorldY;
    u8 k;
    u8 i;
    MinimapRow* row;
    MinimapRow* rows;
    int v;
    u8 j;
    int n;
    int boxTargetWidth;
    MinimapTextBox* box;
    int savedCharset;
    int boxW;
    int boxH;
    s16 xc;
    int xl;
    int xr;
    int sv;
    u32 texW, texH;
    f32 s2, fz, panx, yrel, xrel, pany, ox, oy, t, e, a, b, tileCoord, cx, cy, frac, fx;
    GameObject* player;
    f32 c2, s1, c1, c3, s3, fv;
    MinimapColor color;
    MinimapColor compassColor;

    mapTextureId = 0;
    i = 0;
    k = 0;
    found = 0;
    oy = ox = gMinimapZero;
    color.value = gMinimapBaseColor;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (player->anim.parent != NULL)
        {
            cell = ((GameObject*)player->anim.parent)->anim.mapEventSlot;
        }
        else
        {
            cell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
        }
        while (!found && i < 0x19)
        {
            if (cell == gMinimapCellTable[i].cellId && mainGetBit(gMinimapCellTable[i].gameBit) != 0)
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
                fx = player->anim.worldPosZ;
                fz = player->anim.worldPosX;
                gMinimapAxisSwap = 1;
            }
            else
            {
                fx = player->anim.worldPosX;
                fz = player->anim.worldPosZ;
                gMinimapAxisSwap = 0;
            }
            playerWorldY = (int)player->anim.worldPosY;
            for (; k < gMinimapCellTable[i].count; k++)
            {
                row = &rows[k];
                if (fx >= row->x0 && fx < row->x1 && fz >= row->z0 && fz < row->z1 && (s16)playerWorldY >= row->y0 &&
                    (s16)playerWorldY < row->y1 && mainGetBit(row->gameBit) != 0)
                {
                    j = 0;
                    v = rows[k].mapId;
                    if (v != 0)
                    {
                        mapTextureId = v;
                    }
                    if (gMinimapLoadedMapId == v)
                    {
                        gMinimapRegionMaxX = -0x8000;
                        gMinimapRegionMaxZ = -0x8000;
                        gMinimapRegionMinX = 0x7fff;
                        gMinimapRegionMinZ = 0x7fff;
                        for (; j < gMinimapCellTable[i].count; j++)
                        {
                            if (mapTextureId == rows[j].mapId)
                            {
                                gMinimapRegionMinX =
                                    (rows[j].x0 < gMinimapRegionMinX) ? rows[j].x0 : gMinimapRegionMinX;
                                gMinimapRegionMaxX =
                                    (rows[j].x1 > gMinimapRegionMaxX) ? rows[j].x1 : gMinimapRegionMaxX;
                                gMinimapRegionMinZ =
                                    (rows[j].z0 < gMinimapRegionMinZ) ? rows[j].z0 : gMinimapRegionMinZ;
                                gMinimapRegionMaxZ =
                                    (rows[j].z1 > gMinimapRegionMaxZ) ? rows[j].z1 : gMinimapRegionMaxZ;
                            }
                        }
                        gMinimapTexU = rows[k].texU;
                        gMinimapTexV = rows[k].texV;
                    }
                    break;
                }
            }
        }
        if ((gMinimapEnabled == 0 && lbl_803DD7BA == 0) || mainGetBit(GAMEBIT_NoMapData) != 0)
        {
            mapTextureId = 0;
        }
        if ((*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER || (gMinimapEnabled == 0 && lbl_803DD7BA == 0) ||
            Camera_GetViewportYOffset() != 0 ||
            (player->objectFlags & MINIMAP_OBJFLAG_PARENT_SLACK) != 0 ||
            objIsCurModelNotZero(player) == 0 || pauseMenuState != 0 || lbl_803DD75B != 0)
        {
            mapTextureId = 0;
            gMinimapFadeAlpha -= 0x20;
            n = gMinimapFadeAlpha;
            if (n < 0)
                n = 0;
            else if (n > 0xff)
                n = 0xff;
            gMinimapFadeAlpha = n;
            gMinimapBoxWidth -= 10;
            n = gMinimapBoxWidth;
            if (n < 0)
                n = 0;
            else if (n > 500)
                n = 500;
            gMinimapBoxWidth = n;
            gMinimapBoxHeight -= 10;
            n = gMinimapBoxHeight;
            if (n < 0)
                n = 0;
            else if (n > 500)
                n = 500;
            gMinimapBoxHeight = n;
        }
        else
        {
            gMinimapBoxHeight += 10;
            n = gMinimapBoxHeight;
            if (n < 0)
                n = 0;
            else if (n > 100)
                n = 100;
            gMinimapBoxHeight = n;
            gMinimapFadeAlpha += 0x20;
            n = gMinimapFadeAlpha;
            if (n < 0)
                n = 0;
            else if (n > 0xff)
                n = 0xff;
            gMinimapFadeAlpha = n;
        }
        if (gMinimapLoadedMapId == mapTextureId)
        {
            gMinimapContentAlpha += 0x20;
            gMinimapContentAlpha = (s16)((gMinimapContentAlpha < 0) ? 0
                                                                    : (s16)((gMinimapContentAlpha > gMinimapFadeAlpha)
                                                                                ? gMinimapFadeAlpha
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
                    gMinimapLoadedMapId = 0;
                }
                if (mapTextureId != 0)
                {
                    minimapTexture = textureLoadAsset(mapTextureId);
                    gMinimapLoadedMapId = mapTextureId;
                }
            }
        }
        if (gMinimapFadeAlpha != 0)
        {
            box = gameTextGetBox(0x83);
            if (gMinimapViewMode == MINIMAP_VIEW_MODE_AREA_NAME && lbl_803DD7A2 != 0 && lbl_803DBA6E > -1)
            {
                boxTargetWidth = 200;
            }
            else
            {
                boxTargetWidth = 0x78;
            }
            if (gMinimapBoxWidth < boxTargetWidth)
            {
                gMinimapBoxWidth += framesThisStep * 8;
                gMinimapBoxWidth = (gMinimapBoxWidth < boxTargetWidth) ? gMinimapBoxWidth : boxTargetWidth;
            }
            else
            {
                gMinimapBoxWidth -= framesThisStep * 8;
                gMinimapBoxWidth = (gMinimapBoxWidth > boxTargetWidth) ? gMinimapBoxWidth : boxTargetWidth;
            }
            box->clipWidth = (u16)(gMinimapBoxWidth - 8);
            gMinimapBoxY = 0x1b8 - gMinimapBoxHeight;
            box->y = gMinimapBoxY;
            drawHudBox(0x32, gMinimapBoxY, gMinimapBoxWidth, gMinimapBoxHeight, gMinimapFadeAlpha & 0xff, 1);
            GXSetScissor(0x32, gMinimapBoxY, gMinimapBoxWidth, gMinimapBoxHeight);
            switch (gMinimapViewMode)
            {
            case MINIMAP_VIEW_MODE_MAP:
                if (minimapTexture != NULL)
                {
                    texW = minimapTexture->width;
                    texH = minimapTexture->height;
                    gMinimapWorldToTexScale = texW / (f32)(gMinimapRegionMaxX - gMinimapRegionMinX);
                    boxW = gMinimapBoxWidth;
                    a = (f32)boxW / (f32)texW;
                    boxH = gMinimapBoxHeight;
                    b = (f32)boxH / (f32)texH;
                    a = (a > b) ? b : a;
                    a = (a < gMinimapMaxZoom) ? a : gMinimapMaxZoom;
                    gMinimapMinZoom = a;
                    if (gMinimapAxisSwap != 0)
                    {
                        xrel = -player->anim.worldPosZ + gMinimapRegionMaxX;
                        yrel = player->anim.worldPosX - gMinimapRegionMinZ;
                    }
                    else
                    {
                        xrel = -player->anim.worldPosX + gMinimapRegionMaxX;
                        yrel = -player->anim.worldPosZ + gMinimapRegionMaxZ;
                    }
                    e = boxW - texW * gMinimapZoom;
                    e = e / 2.0f;
                    t = 0.0f;
                    t = (t > e) ? t : e;
                    panx = -t;
                    e = boxH - texH * gMinimapZoom;
                    e = e / 2.0f;
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
                    tileCoord = ox / gMinimapZoom;
                    mapTileU = tileCoord;
                    frac = gMinimapZoom * (tileCoord - (f32)mapTileU);
                    tileCoord = oy / gMinimapZoom;
                    mapTileV = tileCoord;
                    fv = gMinimapZoom * (tileCoord - mapTileV);
                    color.channels.a = gMinimapContentAlpha;
                    color.channels.r = 0x20;
                    color.channels.g = 0x4d;
                    color.channels.b = 0x84;
                    hudDrawRect(0x32, gMinimapBoxY, boxW + 0x32, gMinimapBoxY + boxH, color.channels);
                    drawPartialTexture(minimapTexture, (gMinimapF50 - panx) - frac,
                                       ((f32)(int)gMinimapBoxY - pany) - fv, gMinimapContentAlpha & 0xff,
                                        (int)(gMinimapF256 * gMinimapZoom), texW - mapTileU, texH - mapTileV, mapTileU, mapTileV);
                    cx = 0.5f + ((gMinimapZoom * (xrel * gMinimapWorldToTexScale) + gMinimapF50) - ox - panx);
                    cy =
                        0.5f + ((gMinimapZoom * (yrel * gMinimapWorldToTexScale) + (f32)(int)gMinimapBoxY) - oy - pany);
                    {
                        color.channels.a = gMinimapContentAlpha;
                        color.channels.r = 0;
                        color.channels.g = 0;
                        color.channels.b = 0;
                        gMinimapArrowScale0 = gMinimapFNeg10;
                        fv = gMinimapFNeg6_67;
                        gMinimapArrowScale1 = fv;
                        gMinimapArrowScale2 = fv;
                        c1 = gMinimapArrowScale0 *
                             mathSinf(gMinimapPi * (f32)player->anim.rotX / gMinimapF32768);
                        s1 = gMinimapArrowScale0 *
                             mathCosf(gMinimapPi * (f32)player->anim.rotX / gMinimapF32768);
                        c2 = gMinimapArrowScale1 *
                             mathSinf(gMinimapPi * (f32)(player->anim.rotX + 0x6000) / gMinimapF32768);
                        s2 = gMinimapArrowScale1 *
                             mathCosf(gMinimapPi * (f32)(player->anim.rotX + 0x6000) / gMinimapF32768);
                        c3 = gMinimapArrowScale2 *
                             mathSinf(gMinimapPi * (f32)(player->anim.rotX - 0x6000) / gMinimapF32768);
                        s3 = gMinimapArrowScale2 *
                             mathCosf(gMinimapPi * (f32)(player->anim.rotX - 0x6000) / gMinimapF32768);
                        hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, color.channels);
                        color.channels.a = gMinimapContentAlpha;
                        color.channels.r = 0xff;
                        color.channels.g = 0xff;
                        color.channels.b = 0;
                        c1 = gMinimapFNeg6 * mathSinf(gMinimapPi * (f32)player->anim.rotX / gMinimapF32768);
                        s1 = gMinimapFNeg6 * mathCosf(gMinimapPi * (f32)player->anim.rotX / gMinimapF32768);
                        c2 = gMinimapFNeg4 *
                             mathSinf(gMinimapPi * (f32)(player->anim.rotX + 0x6000) / gMinimapF32768);
                        s2 = gMinimapFNeg4 *
                             mathCosf(gMinimapPi * (f32)(player->anim.rotX + 0x6000) / gMinimapF32768);
                        c3 = gMinimapFNeg4 *
                             mathSinf(gMinimapPi * (f32)(player->anim.rotX - 0x6000) / gMinimapF32768);
                        s3 = gMinimapFNeg4 *
                             mathCosf(gMinimapPi * (f32)(player->anim.rotX - 0x6000) / gMinimapF32768);
                        hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, color.channels);
                    }
                }
                else
                {
                    gameTextSetCursor(box->cursorX, box->cursorY, 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box->clipWidth = (u16)((n > 2) ? n : 2);
                    box->clipWidth = (box->clipWidth < box->width) ? box->clipWidth : box->width;
                    n = gMinimapBoxHeight;
                    box->cursorY = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box->width, box->cursorY, 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    savedCharset = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x458);
                    gameTextSetCharset(savedCharset, 3);
                    gameTextResetCursor(2);
                }
                break;
            case MINIMAP_VIEW_MODE_RADAR:
                Minimap_drawCompassBlip();
                if (gMinimapRadarTarget == NULL)
                {
                    Minimap_drawCompassNeedle();
                    gameTextSetCursor(box->cursorX, box->cursorY, 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box->clipWidth = (u16)((n > 2) ? n : 2);
                    box->clipWidth = (box->clipWidth < box->width) ? box->clipWidth : box->width;
                    n = gMinimapBoxHeight;
                    box->cursorY = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box->width, box->cursorY, 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    savedCharset = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x459);
                    gameTextSetCharset(savedCharset, 3);
                    gameTextResetCursor(2);
                }
                break;
            case MINIMAP_VIEW_MODE_AREA_NAME:
                if (lbl_803DD7A2 != 0 && lbl_803DBA6E > -1)
                {
                    if (gMinimapAreaNameDelay == 0)
                    {
                        gameTextSetCursor(box->cursorX, box->cursorY, 1);
                        gameTextResetCursor(1);
                        box->clipWidth = gMinimapBoxWidth;
                        box->cursorY = gMinimapBoxHeight;
                        gameTextSetCursor(box->cursorX, box->cursorY, 2);
                        gameTextSetColor(0, 0xff, 0, lbl_803DD7A2 & 0xff);
                        gameTextShow(lbl_803DBA6E + 10000);
                        gameTextResetCursor(2);
                    }
                }
                else if (gMinimapEnabled != 0)
                {
                    Minimap_drawCompassNeedle();
                    gameTextSetCursor(box->cursorX, box->cursorY, 1);
                    gameTextResetCursor(1);
                    n = gMinimapBoxWidth;
                    box->clipWidth = (u16)((n > 2) ? n : 2);
                    box->clipWidth = (box->clipWidth < box->width) ? box->clipWidth : box->width;
                    n = gMinimapBoxHeight;
                    box->cursorY = (u16)((n > 2) ? n : 2);
                    gameTextSetCursor(box->width, box->cursorY, 2);
                    gameTextSetColor(0, 0xff, 0, gMinimapFadeAlpha & 0xff);
                    savedCharset = gameTextGetCharset();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x45a);
                    gameTextSetCharset(savedCharset, 3);
                    gameTextResetCursor(2);
                }
                break;
            }
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawTexture(gMinimapCompassTexture, gMinimapF32, (f32)(int)(gMinimapBoxY - 0x14), gMinimapFadeAlpha & 0xff, 0x100);
            if (gMinimapFadeAlpha != 0)
            {
                compassColor.channels.a = gMinimapContentAlpha;
                compassColor.channels.r = 0xff;
                compassColor.channels.g = 0xff;
                compassColor.channels.b = 0;
                xc = (s16)(gMinimapBoxY - 4);
                {
                    if (gMinimapViewMode == MINIMAP_VIEW_MODE_MAP && minimapTexture != NULL)
                    {
                        if (gMinimapZoom < gMinimapMaxZoom)
                        {
                            t = (f32)(sv = xc - 0x14);
                            hudDrawTriangle(gMinimapF44, t, gMinimapF52, (f32)sv, gMinimapF48,
                                            (f32)(xc - 0x1a), compassColor.channels);
                        }
                        if (gMinimapZoom > gMinimapMinZoom)
                        {
                            t = (f32)(sv = xc + 0x14);
                            hudDrawTriangle(gMinimapF44, t, gMinimapF52, (f32)sv, gMinimapF48,
                                            (f32)(xc + 0x1a), compassColor.channels);
                        }
                    }
                    t = (f32)(xl = xc - 4);
                    e = (f32)(xr = xc + 4);
                    a = (f32)(sv = xc);
                    hudDrawTriangle(gMinimapF28, t, gMinimapF28, e, gMinimapF22, a, compassColor.channels);
                    hudDrawTriangle(gMinimapF68, xl, gMinimapF68, xr, gMinimapF74, xc, compassColor.channels);
                }
            }
        }
    }
    return 0;
}

u16 getMinimapY(void)
{
    return gMinimapBoxY;
}

u8 isAreaNameTextActive(void)
{
    u32 act = 0;
    if (gMinimapViewMode == MINIMAP_VIEW_MODE_AREA_NAME && gMinimapEnabled != 0)
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

PPCWGPipe GXWGFifo : (0xCC008000);

void Minimap_drawCompassNeedle(void)
{
    MinimapColor color;
    f32 c0;
    f32 s0;
    f32 c1;
    f32 s1;
    f32 cc2;
    f32 s2;
    int y;

    color.value = gMinimapCompassColor;
    color.channels.a = gMinimapFadeAlpha;
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
    y = gMinimapBoxY + 0x32;
    hudDrawTriangle(gMinimapF110 - c0, y - s0, gMinimapF110 - c1, y - s1, gMinimapF110 - cc2, y - s2,
                    color.channels);
}

void Minimap_drawCompassBlip(void)
{
    u8 count;
    u8 i;
    int pulseOn;
    ObjModel* model;

    count = 2;
    viewFn_80129cbc(gMinimapF43, gMinimapF110, gMinimapF390);
    pulseOn = (gMinimapBlipPulse >> 3) & 1;
    if (pulseOn != 0)
    {
        if (gMinimapBlipObjects[1]->anim.bankIndex == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_and_suck_lp);
        }
    }
    gMinimapBlipObjects[1]->anim.bankIndex = pulseOn;
    if ((u32)gMinimapRadarTarget == 0)
    {
        count = 1;
    }
    for (i = 0; i < count; i++)
    {
        objRender(0, 0, 0, 0, gMinimapBlipObjects[i], 1);
        model = Obj_GetActiveModel((GameObject*)gMinimapBlipObjects[i]);
        model->bufferFlags = (u16)(model->bufferFlags & ~0x8);
        gMinimapBlipObjects[i]->anim.renderAlpha = 255;
    }
    viewFn_80129c74();
}

void Minimap_setupCompassBlip(void)
{
    f32 scale;
    f32 posZ;
    f32 center;
    f32 posY;
    f32 posX;
    u8 i;

    i = 0;
    posX = gMinimapFNeg15;
    posY = gMinimapFNeg9_8;
    center = gMinimapZero;
    posZ = gMinimapFNeg40;
    scale = gMinimapF0_05;
    for (; i < 2; i++)
    {
        gMinimapBlipObjects[i] = (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(32, MINIMAP_COMMAND_MENU_OBJ_BASE + i), 4, -1, -1, 0);
        ((GameObject*)gMinimapBlipObjects[i])->anim.localPosX = posX;
        ((GameObject*)gMinimapBlipObjects[i])->anim.localPosY = posY;
        ((GameObject*)gMinimapBlipObjects[i])->anim.localPosX = center;
        ((GameObject*)gMinimapBlipObjects[i])->anim.localPosY = center;
        ((GameObject*)gMinimapBlipObjects[i])->anim.localPosZ = posZ;
        ((GameObject*)gMinimapBlipObjects[i])->anim.rotX = 2000;
        ((GameObject*)gMinimapBlipObjects[i])->anim.rotY = 0;
        ((GameObject*)gMinimapBlipObjects[i])->anim.rootMotionScale = scale;
    }
}

static inline void Minimap_freeObjectSlots(GameObject** slots, int count)
{
    u8 z[1];
    GameObject* null;

    z[0] = 0;
    null = (GameObject*)z[0];
    while ((u32)z[0] < count)
    {
        if (slots[(u8)z[0]] != NULL)
        {
            Obj_FreeObject(slots[(u8)z[0]]);
            slots[(u8)z[0]] = null;
        }
        z[0]++;
    }
}

void fn_80133934(void)
{
    if (minimapTexture != NULL)
    {
        textureFree((Texture*)(minimapTexture));
        minimapTexture = NULL;
        gMinimapLoadedMapId = 0;
    }
}

void Minimap_frameStart(void)
{
    int player;
    u16 sfx;
    int held;
    int pressed;
    CameraViewSlot* slot;
    int targetAngle;
    s16 angleDelta;
    s16 areaNameId;
    f32 t;
    f32 old;
    f32 pw;
    f32 dist = gMinimapFltMax;

    sfx = 0;
    player = (int)Obj_GetPlayerObject();
    if ((void*)player == NULL || (*gCameraInterface)->getMode() == CAMMODE_VIEWFINDER ||
        Camera_GetViewportYOffset() != 0 || (((GameObject*)player)->objectFlags & MINIMAP_OBJFLAG_PARENT_SLACK) != 0 ||
        objIsCurModelNotZero((void*)player) == 0 || pauseMenuState != 0)
    {
        if (gMinimapZoomSfxActive != 0)
        {
            Sfx_StopFromObject(0, SFXTRIG_pda_compassbeep_3f0);
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
                Sfx_StopFromObject(0, SFXTRIG_pda_compassbeep_3f0);
                gMinimapZoomSfxActive = 0;
            }
        }
        else
        {
            if (gMinimapRadarInited == 0)
            {
                gMinimapRadarInited = 1;
                Minimap_setupCompassBlip();
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
                        gMinimapViewMode = MINIMAP_VIEW_MODE_AREA_NAME;
                    }
                }
                else if ((pressed & 2) != 0)
                {
                    gMinimapViewMode += 1;
                    sfx = 0x3ed;
                    if (gMinimapViewMode > MINIMAP_VIEW_MODE_AREA_NAME)
                    {
                        gMinimapViewMode = MINIMAP_VIEW_MODE_MAP;
                    }
                }
            }
            if (lbl_803DD7BA != 0)
            {
                if (gMinimapSavedViewMode == -1)
                {
                    gMinimapSavedViewMode = gMinimapViewMode;
                }
                gMinimapViewMode = MINIMAP_VIEW_MODE_AREA_NAME;
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
            case MINIMAP_VIEW_MODE_MAP:
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
                t = (gMinimapZoomStep < gMinimapZoomStepMin)
                        ? gMinimapZoomStepMin
                        : ((gMinimapZoomStep > gMinimapZoomStepMax) ? gMinimapZoomStepMax : gMinimapZoomStep);
                gMinimapZoomStep = t;
                old = gMinimapZoom;
                gMinimapZoom = old * t;
                t = (gMinimapZoom < gMinimapMinZoom)
                        ? gMinimapMinZoom
                        : ((gMinimapZoom > gMinimapMaxZoom) ? gMinimapMaxZoom : gMinimapZoom);
                gMinimapZoom = t;
                if (t != old)
                {
                    if (gMinimapZoomSfxActive == 0)
                    {
                        Sfx_PlayFromObject(0, SFXTRIG_pda_compassbeep_3f0);
                        gMinimapZoomSfxActive = 1;
                    }
                }
                else
                {
                    if (gMinimapZoomSfxActive != 0)
                    {
                        Sfx_StopFromObject(0, SFXTRIG_pda_compassbeep_3f0);
                        gMinimapZoomSfxActive = 0;
                    }
                }
                break;
            case MINIMAP_VIEW_MODE_RADAR:
                if (gMinimapZoomSfxActive != 0)
                {
                    Sfx_StopFromObject(0, SFXTRIG_pda_compassbeep_3f0);
                    gMinimapZoomSfxActive = 0;
                }
                gMinimapRadarTarget = (GameObject*)ObjGroup_FindNearestObject(FUELCELL_OBJGROUP, (GameObject*)player, &dist);
                if ((void*)gMinimapRadarTarget != NULL)
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
                    targetAngle =
                        getAngle(((GameObject*)gMinimapRadarTarget)->anim.localPosX - ((GameObject*)player)->anim.localPosX,
                                 ((GameObject*)gMinimapRadarTarget)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ);
                    targetAngle = slot->yaw + targetAngle;
                    angleDelta = targetAngle - (u16)((GameObject*)gMinimapBlipObjects[1])->anim.rotZ;
                    if (angleDelta > 0x8000)
                    {
                        angleDelta = (angleDelta - 0x10000) + 1;
                    }
                    if (angleDelta < -0x8000)
                    {
                        angleDelta += 0xffff;
                    }
                    gMinimapBlipObjects[1]->anim.rotZ = gMinimapBlipObjects[1]->anim.rotZ + angleDelta / 5;
                }
                break;
            case MINIMAP_VIEW_MODE_AREA_NAME:
                if (gMinimapZoomSfxActive != 0)
                {
                    Sfx_StopFromObject(0, SFXTRIG_pda_compassbeep_3f0);
                    gMinimapZoomSfxActive = 0;
                }
                areaNameId = lbl_803DBA6E;
                if (areaNameId != gMinimapPrevAreaNameId)
                {
                    switch (areaNameId)
                    {
                    case -1:
                        sfx = 0x3ef;
                        break;
                    default:
                        sfx = 0x3ee;
                        break;
                    }
                }
                gMinimapPrevAreaNameId = areaNameId;
                break;
            }
            if (sfx != 0)
            {
                Sfx_PlayFromObject(0, sfx);
            }
        }
    }
}

void Minimap_release(void)
{
    if (minimapTexture != NULL)
        textureFree((Texture*)(minimapTexture));
    textureFree((Texture*)(gMinimapCompassTexture));
    Minimap_freeObjectSlots(gMinimapBlipObjects, 2);
    minimapTexture = NULL;
    gMinimapCompassTexture = NULL;
}

void Minimap_initialise(void)
{
    gMinimapCompassTexture = textureLoadAsset(MINIMAP_TEXTURE_COMPASS);
    gMinimapBoxY = 340;
}

u32 lbl_8031C5D0[10] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00040000,
                        (u32)Minimap_initialise,
                        (u32)Minimap_release,
                        0x00000000,
                        (u32)Minimap_frameStart,
                        (u32)Minimap_update,
                        0x00000000};
u32 lbl_8031C5F8[10] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00050000,
                        (u32)dll_3F_initialise,
                        (u32)dll_3F_release,
                        0x00000000,
                        (u32)dll_3F_frameStart_ret_0,
                        (u32)dll_3F_frameEnd_nop,
                        (u32)dll_3F_updateTimerReadout};
