#include "main/texture.h"
#include "track/intersect_hud_api.h"
#include "main/gametext_box_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "sys/objects.h"
#include "main/model.h"
#include "main/objprint_render_api.h"
#include "main/gamebits.h"
#include "dolphin/gx/GXCull.h"
#include "main/pad.h"
#include "main/camera.h"
#include "main/objtype.h"
#include "main/lightmap_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/minimap_api.h"
#include "main/textrender_api.h"
#include "main/pause_menu_api.h"
#include "main/gametext_color_api.h"
#include "dlls/objects/291_fuelCell.h"
#include "dlls/object_descriptor.h"
#include "main/dll/player_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_api.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"

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

#define MINIMAP_TEXTURE_COMPASS 0xBE5

#define MINIMAP_COMMAND_MENU_OBJ_BASE 2010

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

MinimapRow gMinimapRowsMap1050[1] = {
    {-10240, -6400, 8320, 16640, -32768, 32767, 0x95, 0, 0, 1050, 0},
};

MinimapRow gMinimapRowsMap1090[1] = {
    {-11520, -7680, 15360, 19200, -32768, 32767, 0x95, 0, 0, 1090, 0},
};

MinimapRow gMinimapRowsMap1106[1] = {
    {-3840, 640, -3200, 0, -32768, 32767, 0x95, 0, 0, 1106, 0},
};

MinimapRow gMinimapRowsMap1054[1] = {
    {-3840, -1920, -5120, -3200, -32768, 32767, 0x95, 0, 0, 1054, 0},
};

MinimapRow gMinimapRowsMap1109[1] = {
    {-7680, -3840, -3840, -640, -32768, 32767, 0x95, 0, 0, 1109, 0},
};

MinimapRow gMinimapRowsMap1055[1] = {
    {-7040, -5760, -640, 1280, -32768, 32767, 0x95, 0, 0, 1055, 0},
};

MinimapRow gMinimapRowsMap1369[1] = {
    {-13440, -8320, -5120, 0, -32768, 32767, 0x95, 0, 0, 1369, 0},
};

MinimapRow gMinimapRowsMap1089[1] = {
    {-8960, -7040, -1920, 0, -32768, 32767, 0x95, 0, 0, 1089, 0},
};

MinimapRow gMinimapRowsMap1324[1] = {
    {-19200, -13440, -16000, -11520, -32768, 32767, 0x95, 0, 0, 1324, 0},
};

MinimapRow gMinimapRowsMap992[1] = {
    {-1280, 4480, -19200, -16000, -32768, 32767, 0x95, 0, 0, 992, 0},
};

MinimapRow gMinimapRowsMap1049[1] = {
    {-4480, 0, -16000, -12160, -32768, 32767, 0x95, 0, 0, 1049, 0},
};

MinimapRow gMinimapRowsMap1045[1] = {
    {10240, 13440, 0, 6400, -32768, 32767, 0x95, 0, 0, 1045, 0},
};

MinimapRow gMinimapRowsMap1046[2] = {
    {-20480, -15360, -640, 1920, -32768, 32767, 0x95, 0, 0, 1046, 0},
    {-17280, -15360, -1920, 1920, -32768, 32767, 0x95, 0, 0, 1046, 0},
};

MinimapRow gMinimapRowsMap1091[1] = {
    {-15360, -13440, -640, 1280, -32768, 32767, 0x95, 0, 0, 1091, 0},
};

MinimapRow gMinimapRowsMap1113[1] = {
    {-7040, -5760, -2560, -1280, -32768, 32767, 0x95, 0, 0, 1113, 0},
};

MinimapRow gMinimapRowsMap1096[1] = {
    {-6400, -1280, 640, 4480, -32768, 32767, 0x95, 0, 0, 1096, 0},
};

MinimapRow gMinimapRowsMap1048[1] = {
    {-1280, 640, 1920, 3200, -32768, 32767, 0x95, 0, 0, 1048, 0},
};

MinimapRow gMinimapRowsMap1047[1] = {
    {2560, 3840, -9600, -6400, -32768, 32767, 0x95, 0, 0, 1047, 0},
};

MinimapRow gMinimapRowsMap1092[1] = {
    {1280, 4480, -10240, -8320, -32768, 32767, 0x95, 0, 0, 1092, 0},
};

MinimapRow gMinimapRowsMap1093[1] = {
    {3200, 3840, -6400, -4480, -32768, 32767, 0x95, 0, 0, 1093, 0},
};

MinimapRow gMinimapRowsMap1056[1] = {
    {1280, 3840, -5120, -1280, -32768, 32767, 0x95, 0, 0, 1056, 0},
};

MinimapRow gMinimapRowsMap1053[1] = {
    {640, 1280, -4480, -2560, -32768, 32767, 0x95, 0, 0, 1053, 0},
};

MinimapRow gMinimapRowsMap1094[1] = {
    {-17920, -12800, 8320, 14080, -32768, 32767, 0x95, 0, 0, 1094, 0},
};

MinimapMapEntry gMinimapCellTable[25] = {
    {gMinimapRowsMap1050, 0x059E, 0x13, 1}, {gMinimapRowsMap1090, 0x059E, 0x1B, 1},
    {gMinimapRowsMap1106, 0x05A2, 0x0E, 1}, {gMinimapRowsMap1054, 0x05A2, 0x47, 1},
    {gMinimapRowsMap1109, 0x05A3, 0x07, 1}, {gMinimapRowsMap1055, 0x05A3, 0x43, 1},
    {gMinimapRowsMap1369, 0x0835, 0x12, 1}, {gMinimapRowsMap1089, 0x0835, 0x45, 1},
    {gMinimapRowsMap1324, 0x082E, 0x0D, 1}, {gMinimapRowsMap992, 0x05A1, 0x0C, 1},
    {gMinimapRowsMap992, 0x05A1, 0x10, 1}, {gMinimapRowsMap992, 0x05A1, 0x0F, 1},
    {gMinimapRowsMap1049, 0x05A1, 0x2B, 1}, {gMinimapRowsMap1045, 0x07E5, 0x0B, 1},
    {gMinimapRowsMap1046, 0x059D, 0x04, 2}, {gMinimapRowsMap1091, 0x059D, 0x46, 1},
    {gMinimapRowsMap1113, 0x05A3, 0x08, 1}, {gMinimapRowsMap1096, 0x05A0, 0x0A, 1},
    {gMinimapRowsMap1048, 0x05A0, 0x38, 1}, {gMinimapRowsMap1047, 0x07E9, 0x32, 1},
    {gMinimapRowsMap1092, 0x07E9, 0x15, 1}, {gMinimapRowsMap1093, 0x07E9, 0x49, 1},
    {gMinimapRowsMap1056, 0x082F, 0x1D, 1}, {gMinimapRowsMap1053, 0x082F, 0x48, 1},
    {gMinimapRowsMap1094, 0x07DD, 0x02, 1},
};

void Minimap_drawCompassBlip(void);
void Minimap_setupCompassBlip(void);
void Minimap_drawCompassNeedle(void);

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

const MinimapColor gMinimapCompassColor = {0x00FF0000};
const MinimapColor gMinimapBaseColor = {0xFFFF0000};

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
    f32 cx, cy, fz, xrel, yrel, panx, pany, ox, oy, t, e, a, b, tileCoord, frac, fx;
    GameObject* player;
    f32 fv;
    MinimapColor color;
    MinimapColor compassColor;

    mapTextureId = 0;
    i = 0;
    k = 0;
    found = 0;
    oy = ox = 0.0f;
    color.value = gMinimapBaseColor.value;
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
        if ((gMinimapEnabled == 0 && gMinimapHelpTextActive == 0) || mainGetBit(GAMEBIT_NoMapData) != 0)
        {
            mapTextureId = 0;
        }
        if ((*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
            (gMinimapEnabled == 0 && gMinimapHelpTextActive == 0) ||
            Camera_GetViewportYOffset() != 0 ||
            (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
            objIsCurModelNotZero(player) == 0 || pauseMenuState != 0 || gTimeListPromptSelection != 0)
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
            if (gMinimapViewMode == MINIMAP_VIEW_MODE_AREA_NAME && gMinimapAreaNameAlpha != 0 && gMinimapAreaNameId > -1)
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
                    a = texW / (f32)(gMinimapRegionMaxX - gMinimapRegionMinX);
                    gMinimapWorldToTexScale = a;
                    boxW = gMinimapBoxWidth;
                    a = (f32)boxW / (f32)texW;
                    boxH = gMinimapBoxHeight;
                    a = (a < (b = (f32)boxH / (f32)texH)) ? a : b;
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
                    e /= 2.0f;
                    t = (0.0f > e) ? 0.0f : e;
                    panx = -t;
                    e = boxH - texH * gMinimapZoom;
                    e /= 2.0f;
                    t = (0.0f > e) ? 0.0f : e;
                    pany = -t;
                    if (panx == 0.0f)
                    {
                        a = gMinimapZoom * (xrel * gMinimapWorldToTexScale) - (f32)(boxW / 2);
                        t = (0.0f > a) ? 0.0f : a;
                        t = (t < (b = texW * gMinimapZoom - boxW)) ? t : b;
                        ox = t;
                    }
                    if (pany == 0.0f)
                    {
                        a = gMinimapZoom * (yrel * gMinimapWorldToTexScale) - (f32)(boxH / 2);
                        t = (0.0f > a) ? 0.0f : a;
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
                    drawPartialTexture(minimapTexture, (50.0f - panx) - frac,
                                       ((f32)(int)gMinimapBoxY - pany) - fv, gMinimapContentAlpha & 0xff,
                                        (int)(256.0f * gMinimapZoom), texW - mapTileU, texH - mapTileV, mapTileU, mapTileV);
                    cx = 0.5f + ((gMinimapZoom * (xrel * gMinimapWorldToTexScale) + 50.0f) - ox - panx);
                    cy =
                        0.5f + ((gMinimapZoom * (yrel * gMinimapWorldToTexScale) + (f32)(int)gMinimapBoxY) - oy - pany);
                    color.channels.a = gMinimapContentAlpha;
                    color.channels.r = 0;
                    color.channels.g = 0;
                    color.channels.b = 0;
                    gMinimapArrowScale0 = -10.0f;
                    fv = -6.67f;
                    gMinimapArrowScale1 = fv;
                    gMinimapArrowScale2 = fv;
                    {
                        f32 s1 = gMinimapArrowScale0 *
                             mathSinf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                        f32 c1 = gMinimapArrowScale0 *
                             mathCosf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                        f32 c2 = gMinimapArrowScale1 *
                             mathSinf(3.1415927f * (f32)(player->anim.rotX + 0x6000) / 32768.0f);
                        f32 s2 = gMinimapArrowScale1 *
                             mathCosf(3.1415927f * (f32)(player->anim.rotX + 0x6000) / 32768.0f);
                        f32 c3 = gMinimapArrowScale2 *
                             mathSinf(3.1415927f * (f32)(player->anim.rotX - 0x6000) / 32768.0f);
                        f32 s3 = gMinimapArrowScale2 *
                             mathCosf(3.1415927f * (f32)(player->anim.rotX - 0x6000) / 32768.0f);
                        hudDrawTriangle(cx - s1, cy - c1, cx - c2, cy - s2, cx - c3, cy - s3, color.channels);
                    }
                    color.channels.a = gMinimapContentAlpha;
                    color.channels.r = 0xff;
                    color.channels.g = 0xff;
                    color.channels.b = 0;
                    {
                        f32 s1 = -6.0f * mathSinf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                        f32 c1 = -6.0f * mathCosf(3.1415927f * (f32)player->anim.rotX / 32768.0f);
                        f32 c2 = -4.0f *
                             mathSinf(3.1415927f * (f32)(player->anim.rotX + 0x6000) / 32768.0f);
                        f32 s2 = -4.0f *
                             mathCosf(3.1415927f * (f32)(player->anim.rotX + 0x6000) / 32768.0f);
                        f32 c3 = -4.0f *
                             mathSinf(3.1415927f * (f32)(player->anim.rotX - 0x6000) / 32768.0f);
                        f32 s3 = -4.0f *
                             mathCosf(3.1415927f * (f32)(player->anim.rotX - 0x6000) / 32768.0f);
                        hudDrawTriangle(cx - s1, cy - c1, cx - c2, cy - s2, cx - c3, cy - s3, color.channels);
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
                if (gMinimapAreaNameAlpha != 0 && gMinimapAreaNameId > -1)
                {
                    if (gMinimapAreaNameDelay == 0)
                    {
                        gameTextSetCursor(box->cursorX, box->cursorY, 1);
                        gameTextResetCursor(1);
                        box->clipWidth = gMinimapBoxWidth;
                        box->cursorY = gMinimapBoxHeight;
                        gameTextSetCursor(box->cursorX, box->cursorY, 2);
                        gameTextSetColor(0, 0xff, 0, gMinimapAreaNameAlpha & 0xff);
                        gameTextShow(gMinimapAreaNameId + 10000);
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
            drawTexture(gMinimapCompassTexture, 32.0f, (f32)(int)(gMinimapBoxY - 0x14), gMinimapFadeAlpha & 0xff, 0x100);
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
                            hudDrawTriangle(44.0f, t, 52.0f, (f32)sv, 48.0f,
                                            (f32)(xc - 0x1a), compassColor.channels);
                        }
                        if (gMinimapZoom > gMinimapMinZoom)
                        {
                            t = (f32)(sv = xc + 0x14);
                            hudDrawTriangle(44.0f, t, 52.0f, (f32)sv, 48.0f,
                                            (f32)(xc + 0x1a), compassColor.channels);
                        }
                    }
                    t = (f32)(xl = xc - 4);
                    e = (f32)(xr = xc + 4);
                    a = (f32)(sv = xc);
                    a = a;
                    hudDrawTriangle(28.0f, t, 28.0f, e, 22.0f, a, compassColor.channels);
                    hudDrawTriangle(68.0f, xl, 68.0f, xr, 74.0f, xc, compassColor.channels);
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

static inline f32 compassTipSin(f32 scale, f32 phase)
{
    return scale * mathSinf((3.1415927f * phase) / 32768.0f);
}

static inline f32 compassTipCos(f32 scale, f32 phase)
{
    return scale * mathCosf((3.1415927f * phase) / 32768.0f);
}

static inline f32 compassNeedleSin(f32 scale, f32 phase, f32 offset)
{
    return scale * mathSinf((3.1415927f * (phase + offset)) / 32768.0f);
}

static inline f32 compassNeedleCos(f32 scale, f32 phase, f32 offset)
{
    return scale * mathCosf((3.1415927f * (phase + offset)) / 32768.0f);
}

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

    color.value = gMinimapCompassColor.value;
    color.channels.a = gMinimapFadeAlpha;
    gMinimapCompassPhase = -(500.0f * timeDelta - gMinimapCompassPhase);
    if (gMinimapCompassPhase > 32768.0f)
    {
        gMinimapCompassPhase -= 65536.0f;
    }
    c0 = compassTipSin(60.0f, gMinimapCompassPhase);
    s0 = compassTipCos(60.0f, gMinimapCompassPhase);
    c1 = compassNeedleSin(2.0f, gMinimapCompassPhase, 24576.0f);
    s1 = compassNeedleCos(2.0f, gMinimapCompassPhase, 24576.0f);
    cc2 = compassNeedleSin(2.0f, gMinimapCompassPhase, -24576.0f);
    s2 = compassNeedleCos(2.0f, gMinimapCompassPhase, -24576.0f);
    y = gMinimapBoxY + 0x32;
    hudDrawTriangle(110.0f - c0, y - s0, 110.0f - c1, y - s1, 110.0f - cc2, y - s2,
                    color.channels);
}

void Minimap_drawCompassBlip(void)
{
    u8 count;
    u8 i;
    int pulseOn;
    ObjModel* model;

    count = 2;
    gameUiBeginOverlayView(43.0f, 110.0f, 390.0f);
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
        model->bufferFlags &= ~0x8;
        gMinimapBlipObjects[i]->anim.renderAlpha = 255;
    }
    gameUiEndOverlayView();
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
    posX = -15.0f;
    posY = -9.8f;
    center = 0.0f;
    posZ = -40.0f;
    scale = 0.05f;
    for (; i < 2; i++)
    {
        gMinimapBlipObjects[i] = (GameObject*)objSetupObject(Obj_AllocObjectSetup(32, MINIMAP_COMMAND_MENU_OBJ_BASE + i), 4, -1, -1, 0);
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

void minimapFreeTexture(void)
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
    GameObject* player;
    u16 sfx;
    int held;
    int pressed;
    Camera* slot;
    int targetAngle;
    s16 angleDelta;
    s16 areaNameId;
    f32 t;
    f32 old;
    f32 pw;
    f32 dist = 3.4028235e38f;

    sfx = 0;
    player = Obj_GetPlayerObject();
    if (player == NULL || (*gCameraInterface)->getMode() == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
        Camera_GetViewportYOffset() != 0 || (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
        objIsCurModelNotZero(player) == 0 || pauseMenuState != 0)
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
        if ((*gGameUIInterface)->isItemBeingUsed(0xc8d) != 0)
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
        if (gMinimapEnabled == 0 && gMinimapHelpTextActive == 0)
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
            if (gMinimapHelpTextActive != 0)
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
                    gMinimapZoomStep *= pw;
                }
                else if ((held & 8) != 0)
                {
                    pw = powfCoreFast(gMinimapZoomOutRate, timeDelta);
                    gMinimapZoomStep *= pw;
                }
                else
                {
                    gMinimapZoomStep = 1.0f;
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
                gMinimapRadarTarget =
                    objGetNearestTypeTo(FUEL_CELL_OBJECT_GROUP, player, &dist);
                if ((void*)gMinimapRadarTarget != NULL)
                {
                    if (dist < 500.0f)
                    {
                        gMinimapBlipPulse += 1;
                        if (dist < 150.0f)
                        {
                            gMinimapBlipPulse += 1;
                        }
                    }
                    else
                    {
                        gMinimapBlipPulse = 0;
                    }
                    slot = Camera_GetCurrent();
                    targetAngle =
                        getAngle(gMinimapRadarTarget->anim.localPosX - player->anim.localPosX,
                                 gMinimapRadarTarget->anim.localPosZ - player->anim.localPosZ);
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
                areaNameId = gMinimapAreaNameId;
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

ObjectDescriptor6 Minimap_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_5_SLOTS,
    (ObjectDescriptorCallback)Minimap_initialise,
    (ObjectDescriptorCallback)Minimap_release,
    0,
    (ObjectDescriptorCallback)Minimap_frameStart,
    (ObjectDescriptorCallback)Minimap_update,
    0,
};
