#include "main/sky_state.h"
#include "main/dll/savegame_env_api.h"
#include "main/dll/savegame_load_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/render_envfx_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits.h"
#include "main/sky_interface.h"
#include "main/dll/cloudaction_interface.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "string.h"
#include "sys/objects.h"
#include "main/objprint_render_api.h"
#include "sys/objects/lifecycle.h"
#include "main/pad.h"
#include "main/curve_eval.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/camera.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/pi_data_file_api.h"
#include "main/pi_frame_api.h"
#include "main/pi_flush_api.h"
#include "main/texture.h"
#include "main/textrender_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/sky.h"
#include "main/sky_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "dlls/object_descriptor.h"
#include "main/loaded_file_flags.h"
#include "track/intersect_screen_api.h"
#include "track/intersect_api.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/mtx.h"
#include "main/lightmap.h"
#include "main/track_dolphin_sky_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "dolphin/mtx/vec.h"
#include "main/vecmath.h"

typedef struct SkyColor
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} SkyColor;

u32 sSkyUnusedD;
SkyColor gSkyCurrentTextureColor;
SkyColor gSkyCurrentAmbientColor;
SkyColor gSkyCurrentLightColor;
u8 gSkySunPositionPrev;
ModelLightStruct* gSkyMoonLight;
u8 gSkyOverrideLightDirectionEnabled;
f32 gSkyOverrideLightIntensity;
u8 gSkyOverrideLightColorEnabled;
SkyColor gSkyOverrideLightColor;
int gSkyObjectsInitialized;
Texture* gSkySkyTexture;
GameObject* gSkyMoonObject;
GameObject* gSkySunObject;
ModelLightStruct* gSkySunLight;
u8 gSkyEnvFxFlags;
s16* gSkyEnvFxGroupBTable;
s16* gSkyEnvFxGroupCTable;
s16* gSkyEnvFxGroupDTable;
s16* gSkyEnvFxGroupATable;
u8* gSkyState;
u16 gSkyMoonAlpha;
u16 gSkySunAlpha;


/* gSkyEnvFxFlags: per-group env-FX trigger enables + update state */
#define SKY_ENVFX_GROUP_C        0x01 /* gSkyEnvFxGroupCTable group (GameBit 0x3ab) */
#define SKY_ENVFX_GROUP_A        0x02 /* gSkyEnvFxGroupATable group (GameBit 0x3ac) */
#define SKY_ENVFX_GROUP_B        0x04 /* gSkyEnvFxGroupBTable group */
#define SKY_ENVFX_GROUP_D        0x08 /* gSkyEnvFxGroupDTable group (weather) */
#define SKY_ENVFX_UPDATE_PENDING 0x10 /* sun position changed; process this frame */
#define SKY_ENVFX_IMMEDIATE      0x20 /* fire acts immediately vs deferred */
/* env-effect ids activated together when the GROUP_D (weather) flag is clear
   (index-style; roles opaque) */
#define SKY_ENVFX_ID_A               0x136
#define SKY_ENVFX_ID_B               0x137
#define SKY_ENVFX_ID_C               0x143
#define SKY_CONFIG_FIELD_COUNT       0xb
#define SKY_CHILD_OBJ_SUN            0x62b /* spawned into gSkySunObject */
#define SKY_CHILD_OBJ_MOON           0x62c /* spawned into gSkyMoonObject */
#define SKY_TEXTURE_SKY              0x5fa /* gSkySkyTexture */
extern f32 gSkyOverrideLightDirection[];
STATIC_ASSERT(sizeof(Vec) == 0xC);
const Vec gSkyBaseSunDirection = {0.0f, 0.0f, 4600.0f};
const Vec gSkyBaseMoonDirection = {0.0f, 0.0f, 4600.0f};
extern int lbl_803E8458;
int skyReservedReturnZeroB(void)
{
    return 0x0;
}

int skyGetDayNo(void)
{
    return (u8)mainGetBit(GAMEBIT_ENV_dayNo);
}

void skySetDayNo(int value)
{
    if ((u8)value >= 0x1c)
    {
        value = 0;
    }
    mainSetBits(GAMEBIT_ENV_dayNo, (u8)value);
}

void skyReservedNopC(void)
{
}

void skyReservedNopB(void)
{
}

void skyRefreshPlayerEnvFx(void)
{
    skyApplyPlayerEnvFx(mainGetBit(GAMEBIT_ENV_dayNo));
}

void skySetEnvFxFlags(u8 value)
{
    void* player;
    int masked;

    gSkyEnvFxFlags = value;
    masked = value;
    masked &= SKY_ENVFX_GROUP_D;
    if (masked == 0)
    {
        player = Obj_GetPlayerObject();
        getEnvfxAct(player, player, SKY_ENVFX_ID_A, 0);
        getEnvfxAct(player, player, SKY_ENVFX_ID_B, 0);
        getEnvfxAct(player, player, SKY_ENVFX_ID_C, 0);
    }
}

void skySetEnvFxRampTables(void* groupB, void* groupA, void* groupC, void* groupD)
{
    gSkyEnvFxGroupBTable = groupB;
    gSkyEnvFxGroupATable = groupA;
    gSkyEnvFxGroupCTable = groupC;
    gSkyEnvFxGroupDTable = groupD;
}

void skyUpdateEnvFx(void)
{
    u8 a;
    u8 b;
    u8 flags;

    a = (u8)(*gSkyInterface)->getSunPosition(0);
    b = mainGetBit(GAMEBIT_ENV_dayNo);
    if (a != gSkySunPositionPrev)
    {
        gSkySunPositionPrev = a;
        if (a == 0)
        {
            b++;
            if (b == 0x1c)
            {
                b = 0;
            }
            mainSetBits(GAMEBIT_ENV_dayNo, b);
        }
        if (gSkyEnvFxFlags != 0)
        {
            gSkyEnvFxFlags |= SKY_ENVFX_UPDATE_PENDING;
        }
    }
    flags = gSkyEnvFxFlags;
    if ((flags & SKY_ENVFX_UPDATE_PENDING) == 0)
    {
        return;
    }
    flags = (u8)(flags & ~SKY_ENVFX_UPDATE_PENDING);
    gSkyEnvFxFlags = flags;
    if ((u32)gSkyEnvFxGroupATable != 0 && (flags & SKY_ENVFX_GROUP_A) != 0 && mainGetBit(GAMEBIT_ENV_disableDayFX2) == 0)
    {
        if ((gSkyEnvFxFlags & SKY_ENVFX_IMMEDIATE) != 0)
        {
            getEnvfxActImmediately(0, 0, gSkyEnvFxGroupATable[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, gSkyEnvFxGroupATable[b], 0);
        }
    }
    if ((u32)gSkyEnvFxGroupBTable != 0 && (gSkyEnvFxFlags & SKY_ENVFX_GROUP_B) != 0)
    {
        if ((gSkyEnvFxFlags & SKY_ENVFX_IMMEDIATE) != 0)
        {
            getEnvfxActImmediately(0, 0, gSkyEnvFxGroupBTable[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, gSkyEnvFxGroupBTable[b], 0);
        }
    }
    if ((u32)gSkyEnvFxGroupCTable != 0 && (gSkyEnvFxFlags & SKY_ENVFX_GROUP_C) != 0 &&
        mainGetBit(GAMEBIT_ENV_disableDayFX1) == 0)
    {
        if ((gSkyEnvFxFlags & SKY_ENVFX_IMMEDIATE) != 0)
        {
            getEnvfxActImmediately(0, 0, gSkyEnvFxGroupCTable[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, gSkyEnvFxGroupCTable[b], 0);
        }
    }
    skyApplyPlayerEnvFx(b);
    gSkyEnvFxFlags &= ~SKY_ENVFX_IMMEDIATE;
}

void skyApplyPlayerEnvFx(u8 idx)
{
    void* player;
    int val;
    s8 alt;

    player = Obj_GetPlayerObject();
    if ((void*)gSkyEnvFxGroupDTable == NULL || player == NULL)
    {
        return;
    }
    if ((gSkyEnvFxFlags & SKY_ENVFX_GROUP_D) == 0)
    {
        return;
    }
    if (mainGetBit(GAMEBIT_ENV_isOutdoor) != 0)
    {
        return;
    }
    alt = (s8)(idx - 1);
    if (alt < 0)
    {
        alt = 27;
    }
    if (gSkyEnvFxGroupDTable[idx] <= 0 || gSkyEnvFxGroupDTable[alt] != gSkyEnvFxGroupDTable[idx])
    {
        getEnvfxAct(player, player, 310, 0);
        getEnvfxAct(player, player, 311, 0);
        getEnvfxAct(player, player, 323, 0);
    }
    val = gSkyEnvFxGroupDTable[idx];
    if (val > 0)
    {
        if (gSkyEnvFxFlags & SKY_ENVFX_IMMEDIATE)
        {
            getEnvfxActImmediately(player, player, val, 0);
        }
        else
        {
            getEnvfxAct(player, player, val, 0);
        }
    }
}

void loadSunAndMoon(void)
{
    GameObject* moonObj;

    if (gSkyObjectsInitialized == 0)
    {
        gSkySunObject = objSetupObject(Obj_AllocObjectSetup(0x20, SKY_CHILD_OBJ_SUN), 4, -1, -1, NULL);
        moonObj = objSetupObject(Obj_AllocObjectSetup(0x20, SKY_CHILD_OBJ_MOON), 4, -1, -1, NULL);
        gSkyMoonObject = moonObj;
        gSkyObjectsInitialized = 1;
        ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(moonObj), moonFxRenderCallback);
    }
}

f32 gSkySunDirection[] = {0.0f, 1.0f, 0.0f};

f32 gSkyMoonDirection[] = {0.0f, 1.0f, 0.0f};

f32 sSkyUnusedColors[] = {
    80.0f,  120.0f, 165.0f, 120.0f, 80.0f,  80.0f, 100.0f, 125.0f,
    100.0f, 80.0f,  255.0f, 220.0f, 190.0f, 220.0f, 255.0f,
};

u8 gSkyColorBlendTable[248] = {
    0,   29,  164, 0,   0,   72,  155, 68,  29,  12,  53,  28,  255, 143, 191, 255, 116, 186, 255, 219, 255, 255, 176,
    255, 255, 255, 255, 232, 211, 255, 130, 255, 255, 79,  163, 255, 180, 255, 255, 111, 167, 255, 255, 255, 165, 245,
    183, 140, 255, 205, 0,   255, 152, 0,   255, 129, 36,  242, 96,  33,  153, 53,  107, 104, 38,  102, 11,  0,   69,
    7,   0,   65,  255, 255, 255, 255, 255, 255, 202, 0,   254, 77,  0,   97,  255, 116, 200, 98,  0,   59,  101, 224,
    127, 0,   83,  44,  254, 254, 19,  0,   105, 38,  255, 254, 38,  205, 45,  61,  255, 253, 0,   169, 19,  57,  254,
    254, 254, 8,   121, 208, 206, 0,   0,   255, 161, 0,   255, 254, 226, 92,  131, 63,  255, 255, 147, 180, 91,  67,
    255, 254, 254, 210, 56,  130, 255, 0,   0,   122, 17,  1,   152, 0,   149, 36,  0,   87,  255, 72,  255, 101, 6,
    101, 255, 230, 131, 255, 176, 47,  254, 0,   0,   63,  0,   0,   92,  142, 255, 0,   0,   92,  153, 198, 255, 0,
    37,  172, 255, 255, 255, 53,  53,  255, 128, 128, 83,  122, 96,  70,  201, 0,   254, 77,  0,   97,  30,  65,  85,
    195, 219, 244, 30,  65,  85,  203, 219, 133, 30,  65,  85,  111, 12,  134, 30,  65,  85,  49,  138, 216, 30,  65,
    85,  255, 213, 81,  30,  65,  85,  255, 12,  0,   0,   0,   0,   0,   0,   0,   0,   0,
};

typedef struct SkyDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback updateEnvfxAct;
    ObjectDescriptorCallback loadLights;
    ObjectDescriptorCallback updateTimeOfDay;
    ObjectDescriptorCallback render;
    ObjectDescriptorCallback getTimeOfDay;
    ObjectDescriptorCallback getClockTime;
    ObjectDescriptorCallback reservedNopA;
    ObjectDescriptorCallback getTransitionTimer;
    ObjectDescriptorCallback getSunPosition;
    ObjectDescriptorCallback setTimeOfDay;
    ObjectDescriptorCallback reservedReturnZeroA;
    ObjectDescriptorCallback timeToDayHourMinute;
    ObjectDescriptorCallback getVisibility;
    ObjectDescriptorCallback renderTimeOfDayBackdrop;
    ObjectDescriptorCallback getCurrentTextureColor;
    ObjectDescriptorCallback getCurrentAmbientAndLightColors;
    ObjectDescriptorCallback reservedNopB;
    ObjectDescriptorCallback reservedNopC;
    ObjectDescriptorCallback setDayNo;
    ObjectDescriptorCallback getDayNo;
    ObjectDescriptorCallback reservedReturnZeroB;
} SkyDllInterface;

SkyDllInterface sky_funcs = {
    0,
    0,
    0,
    0x00033FB0,
    0,
    0,
    0,
    (ObjectDescriptorCallback)skyUpdateEnvfxAct,
    (ObjectDescriptorCallback)skyLoadLights,
    (ObjectDescriptorCallback)skyUpdateTimeOfDay,
    (ObjectDescriptorCallback)renderSky,
    (ObjectDescriptorCallback)getTimeOfDay,
    (ObjectDescriptorCallback)skyGetClockTime,
    (ObjectDescriptorCallback)skyReservedNopA,
    (ObjectDescriptorCallback)skyGetTimer,
    (ObjectDescriptorCallback)getSunPos,
    (ObjectDescriptorCallback)pDll_Sky_setTimeOfDay_nop,
    (ObjectDescriptorCallback)skyReservedReturnZeroA,
    (ObjectDescriptorCallback)skyTimeToDayHourMinute,
    (ObjectDescriptorCallback)skyGetVisibility,
    (ObjectDescriptorCallback)skyRenderTimeOfDayBackdrop,
    (ObjectDescriptorCallback)skyGetCurrentTextureColor,
    (ObjectDescriptorCallback)skyGetCurrentAmbientAndLightColors,
    (ObjectDescriptorCallback)skyReservedNopB,
    (ObjectDescriptorCallback)skyReservedNopC,
    (ObjectDescriptorCallback)skySetDayNo,
    (ObjectDescriptorCallback)skyGetDayNo,
    (ObjectDescriptorCallback)skyReservedReturnZeroB,
};

void skySetSlotFlag80(int flags, u8 mode)
{
    u8* env;
    SkyState* sky;
    int i;
    u8* entry;

    for (i = 0; i < 2; i++)
    {
        if ((flags & (1 << i)) != 0)
        {
            if (mode != 0)
            {
                ((SkyState*)gSkyState)->lights[i].flags.unused80 = 1;
            }
            else
            {
                entry = gSkyState;
                entry = entry + i * 0xa4;
                ((SkyLight*)(entry + 0x20))->flags.unused80 = 0;
            }
        }
    }
    sky = (SkyState*)gSkyState;
    sky->lights[2].flags.unused80 =
        sky->lights[sky->currentLightIndex].flags.unused80;
    env = (u8*)saveGameGetEnvState();
    if (getSaveGameLoadStatus() == 0)
    {
        for (i = 0; i < 2; i++)
        {
            if (((SkyState*)gSkyState)->lights[i].flags.unused80 != 0)
            {
                env[0x40] |= (2 << i);
            }
            else
            {
                env[0x40] &= ~(2 << i);
            }
        }
    }
}

u8 skyGetSlotFlag80(int slot)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky != NULL)
    {
        return sky->lights[slot].flags.unused80;
    }
    return 0;
}

int skyGetSlotBlendAlpha(int slot)
{
    u8* sky;

    sky = gSkyState;
    if (sky != NULL)
    {
        return sky[slot * 0xa4 + 0xc0];
    }
    return 0xff;
}

void skySetLightIndex(int mode, f32 brightness)
{
    u8* env;
    u8* env2;
    u32 cloudMode;
    int bit;
    f32 unset;
    f32 fullBlend;
    int idx;

    env = (u8*)saveGameGetEnvState();
    if (((SkyState*)gSkyState)->currentLightIndex != mode)
    {
        ((SkyState*)gSkyState)->previousLightIndex = ((SkyState*)gSkyState)->currentLightIndex;
        ((SkyState*)gSkyState)->currentLightIndex = mode;
        unset = 0.0f;
        if (brightness != unset)
        {
            ((SkyState*)gSkyState)->lightBlendRate = 1.0f / (60.0f * brightness);
            ((SkyState*)gSkyState)->lightBlendFactor = unset;
        }
        else
        {
            fullBlend = 1.0f;
            ((SkyState*)gSkyState)->lightBlendRate = fullBlend;
            ((SkyState*)gSkyState)->lightBlendFactor = fullBlend;
        }
        cloudMode = ((SkyLight*)(gSkyState + (idx = mode * 0xa4) + 0x20))->flags.cloud;
        if (cloudMode != 0)
        {
            setDrawCloudsAndLights(cloudMode - 1);
        }
        ((SkyState*)gSkyState)->lights[2].flags.unused80 =
            ((SkyLight*)(gSkyState + idx + 0x20))->flags.unused80;
        ((SkyState*)gSkyState)->lights[2].flags.visibility =
            ((SkyLight*)(gSkyState + idx + 0x20))->flags.visibility;
        env2 = (u8*)saveGameGetEnvState();
        if (getSaveGameLoadStatus() == 0)
        {
            for (bit = 0; bit < 2; bit++)
            {
                if (((SkyState*)gSkyState)->lights[bit].flags.unused80 != 0)
                {
                    env2[0x40] |= 2 << bit;
                }
                else
                {
                    env2[0x40] &= ~(2 << bit);
                }
            }
        }
        if (mode != 0)
        {
            env[0x40] |= 0x10;
        }
        else
        {
            env[0x40] &= ~0x10;
        }
    }
}

int skyGetCurrentLightIndex(void)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky != NULL)
    {
        return sky->currentLightIndex;
    }
    return 0;
}

void skyGetCurrentTextureColor(u8* red, u8* green, u8* blue)
{
    if (gSkyState != NULL)
    {
        *red = gSkyCurrentTextureColor.r;
        *green = gSkyCurrentTextureColor.g;
        *blue = gSkyCurrentTextureColor.b;
        return;
    }
    *red = 0xff;
    *green = 0xff;
    *blue = 0xff;
}

void skyGetCurrentAmbientAndLightColors(u8* ambientRed, u8* ambientGreen, u8* ambientBlue, u8* lightRed, u8* lightGreen,
                                        u8* lightBlue)
{
    u8 red;
    u8 green;
    u8 blue;

    if (gSkyOverrideLightColorEnabled != 0)
    {
        red = gSkyOverrideLightColor.r;
        *ambientRed = red;
        *lightRed = red;
        green = gSkyOverrideLightColor.g;
        *ambientGreen = green;
        *lightGreen = green;
        blue = gSkyOverrideLightColor.b;
        *ambientBlue = blue;
        *lightBlue = blue;
        return;
    }

    if (gSkyState != NULL)
    {
        *ambientRed = gSkyCurrentAmbientColor.r;
        *ambientGreen = gSkyCurrentAmbientColor.g;
        *ambientBlue = gSkyCurrentAmbientColor.b;
        *lightRed = gSkyCurrentLightColor.r;
        *lightGreen = gSkyCurrentLightColor.g;
        *lightBlue = gSkyCurrentLightColor.b;
        return;
    }

    *ambientRed = 0xff;
    *ambientGreen = 0xff;
    *ambientBlue = 0xff;
    *lightRed = 0xff;
    *lightGreen = 0xff;
    *lightBlue = 0xff;
}

Texture* skyGetSkyTexture(void)
{
    return gSkySkyTexture;
}

void skyBuildSunModelMatrix(Mtx mtx)
{
    f32 scale;
    Mtx scaleMtx;

    scale = 1.0f / gSkySunObject->anim.rootMotionScale;
    PSMTXScale(scaleMtx, scale, scale, scale);
    Obj_BuildWorldTransformMatrix(gSkySunObject, (f32*)mtx, 0);
    PSMTXConcat(mtx, scaleMtx, mtx);
}

u8 skyGetSunRenderAlpha(int slot)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky == NULL)
    {
        return 0;
    }

    if (sky->lights[slot].flags.unused80 != 0)
    {
        return 0;
    }
    return gSkySunObject->anim.renderAlpha;
}

void skySetOverrideLightColor(u8 red, u8 green, u8 blue)
{
    gSkyOverrideLightColor.r = red;
    gSkyOverrideLightColor.g = green;
    gSkyOverrideLightColor.b = blue;
}

void skySetOverrideLightColorEnabled(u8 enabled)
{
    gSkyOverrideLightColorEnabled = enabled;
}

void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity)
{
    gSkyOverrideLightDirection[0] = x;
    gSkyOverrideLightDirection[1] = y;
    gSkyOverrideLightDirection[2] = z;
    gSkyOverrideLightIntensity = intensity;
    PSVECNormalize((Vec*)gSkyOverrideLightDirection, (Vec*)gSkyOverrideLightDirection);
}

void skySetOverrideLightDirectionEnabled(u8 enabled)
{
    gSkyOverrideLightDirectionEnabled = enabled;
}

void skyGetObjectLightDirection(GameObject* obj, f32* x, f32* y, f32* z)
{
    u8* lights[4];
    Vec dir;
    int count;
    f32 lx;
    f32 ly;
    f32 lz;
    u8** p;
    int i;
    int slot;
    u8 flag;
    f32 mag;
    u8* sk;
    u8* found;
    u8* cur;
    int offset;

    found = NULL;
    cur = NULL;
    if (gSkyOverrideLightDirectionEnabled != 0)
    {
        *x = gSkyOverrideLightDirection[0];
        *y = gSkyOverrideLightDirection[1];
        *z = gSkyOverrideLightDirection[2];
    }
    else
    {
        slot = obj->lightColorSlot;
        if (gSkyState != NULL)
        {
            flag = ((SkyState*)gSkyState)->lights[slot].flags.unused80;
        }
        else
        {
            flag = 0;
        }
        if (flag != 0)
        {
            modelLightStruct_selectObjectLights(obj, (ModelLightStruct**)lights, 4, (s32*)&count, 2);
            if (count > 0)
            {
                if ((u8*)obj->anim.modelState != NULL)
                {
                    found = obj->anim.modelState->lastSelectedLight;
                }
                cur = lights[0];
                if (found != lights[0] && found != NULL)
                {
                    p = &lights[1];
                    for (i = count; i > 1; i--)
                    {
                        if (*p == found)
                        {
                            if (-((ModelLightStruct*)cur)->selectionScore <
                                1.0013f * -((ModelLightStruct*)found)->selectionScore)
                            {
                                cur = found;
                            }
                            break;
                        }
                        p++;
                    }
                }
                modelLightStruct_getWorldPosition((ModelLightStruct*)cur, &lx, &ly, &lz);
                dir.x = obj->anim.worldPosX - lx;
                dir.y = obj->anim.worldPosY - ly;
                dir.z = obj->anim.worldPosZ - lz;
                mag = PSVECMag(&dir);
                if (mag > 0.0f)
                {
                    mag = 1.0f / mag;
                    PSVECScale(&dir, &dir, mag);
                    *x = dir.x;
                    *y = dir.y;
                    *z = dir.z;
                }
            }
            else
            {
                cur = NULL;
                dir.x = 0.5f;
                dir.y = (-1.0f);
                dir.z = 0.5f;
                PSVECNormalize(&dir, &dir);
                *x = dir.x;
                *y = dir.y;
                *z = dir.z;
            }
        }
        else
        {
            if (gSkyState == NULL)
            {
                *x = 0.0f;
                *y = (-1.0f);
                *z = 0.0f;
            }
            else
            {
                offset = slot * 0xa4;
                sk = gSkyState + offset;
                *x = ((SkyState*)sk)->lights[0].directionX;
                sk = gSkyState + offset;
                *y = ((SkyState*)sk)->lights[0].directionY;
                sk = gSkyState + offset;
                sk = (u8*)sk;
                *z = ((SkyState*)sk)->lights[0].directionZ;
            }
        }
    }
    if ((u8*)obj->anim.modelState != NULL)
    {
        obj->anim.modelState->lastSelectedLight = cur;
    }
}

void skySetLightDirection(int flags, f32 x, f32 y, f32 z)
{
    int bit;

    if (gSkyState == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideDirectionX = x;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideDirectionY = y;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideDirectionZ = z;
        }
    }
}

void skySetAmbientColor(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (gSkyState == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideAmbientR = red;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideAmbientG = green;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideAmbientB = blue;
        }
    }
}

void skySetMoonColor(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (gSkyState == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideMoonColorR = red;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideMoonColorG = green;
            ((SkyState*)(gSkyState + bit * 0xa4))->lights[0].overrideMoonColorB = blue;
        }
    }
}

void skySetBaseColor(int flags, u8 red, u8 green, u8 blue, u8 moonScale, u8 ambientScale)
{
    int base;
    int r1, g1, b1, r2, g2, b2;
    int bit;

    if (gSkyState == NULL)
    {
        return;
    }
    bit = 0;
    base = 0;
    r1 = red * moonScale >> 8;
    g1 = green * moonScale >> 8;
    b1 = blue * moonScale >> 8;
    r2 = red * ambientScale >> 8;
    g2 = green * ambientScale >> 8;
    b2 = blue * ambientScale >> 8;
    for (; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            ((SkyState*)(gSkyState + base))->lights[0].overrideSunColorR = red;
            ((SkyState*)(gSkyState + base))->lights[0].overrideSunColorG = green;
            ((SkyState*)(gSkyState + base))->lights[0].overrideSunColorB = blue;
            ((SkyState*)(gSkyState + base))->lights[0].overrideMoonColorR = r1;
            ((SkyState*)(gSkyState + base))->lights[0].overrideMoonColorG = g1;
            ((SkyState*)(gSkyState + base))->lights[0].overrideMoonColorB = b1;
            ((SkyState*)(gSkyState + base))->lights[0].overrideAmbientR = r2;
            ((SkyState*)(gSkyState + base))->lights[0].overrideAmbientG = g2;
            ((SkyState*)(gSkyState + base))->lights[0].overrideAmbientB = b2;
        }
        base += 0xa4;
    }
}

void skySetLightsEnabled(int flags, u8 enabled, int startComplete)
{
    SkyState* sky;
    u32 flagBit;
    u8 stateActive;

    sky = (SkyState*)gSkyState;
    if (sky == NULL)
    {
        return;
    }

    for (flagBit = 0; flagBit < 2; flagBit++)
    {
        if ((flags & (1 << flagBit)) != 0)
        {
            sky = (SkyState*)gSkyState;
            stateActive = sky->lights[flagBit].flags.active;
            if (stateActive != enabled)
            {
                if (startComplete != 0)
                {
                    sky->lights[flagBit].unk9C = 1.0f;
                }
                else
                {
                    sky->lights[flagBit].unk9C = 0.0f;
                }
            }
            sky = (SkyState*)gSkyState;
            sky->lights[flagBit].flags.active = enabled;
        }
    }
}

void skyGetSunLightDirection(int slot, f32* x, f32* y, f32* z)
{
    u8* sky;
    int offset;
    f32 fallback;

    if (gSkyState == NULL)
    {
        fallback = 0.0f;
        *x = fallback;
        *y = (-1.0f);
        *z = fallback;
        return;
    }

    offset = slot * 0xa4;
    sky = gSkyState + offset;
    *x = ((SkyState*)sky)->lights[0].directionX;
    sky = gSkyState + offset;
    *y = ((SkyState*)sky)->lights[0].directionY;
    sky = gSkyState + offset;
    sky = (u8*)sky;
    *z = ((SkyState*)sky)->lights[0].directionZ;
}

void objGetSunColor(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky;
    int offset;

    sky = gSkyState;
    if (sky == NULL)
    {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
    }
    else
    {
        offset = slot * 0xa4;
        *red = gSkyState[offset + 0x78];
        *green = gSkyState[offset + 0x79];
        *blue = gSkyState[offset + 0x7a];
    }

    *red = (u8)((*red * colorScale) >> 8);
    *green = (u8)((*green * colorScale) >> 8);
    *blue = (u8)((*blue * colorScale) >> 8);
}

void skyGetSunColor(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky = gSkyState;
    if (sky == NULL) {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
    } else {
        int offset = slot * 0xa4;
        *red = gSkyState[offset + 0x78];
        *green = gSkyState[offset + 0x79];
        *blue = gSkyState[offset + 0x7a];
    }
}

void skyGetAmbientColor(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky;
    int offset;

    sky = gSkyState;
    if (sky == NULL)
    {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
        return;
    }

    offset = slot * 0xa4;
    *red = gSkyState[offset + 0x88];
    *green = gSkyState[offset + 0x89];
    *blue = gSkyState[offset + 0x8a];
}

void skyApplyLightSlot(int slot)
{
    int offset;
    SkyState* sky;

    if (gSkySunLight != NULL)
    {
        offset = slot * 0xa4;
        sky = (SkyState*)(gSkyState + offset);
        modelLightStruct_setDirection(gSkySunLight, sky->lights[0].directionX,
                                      sky->lights[0].directionY, sky->lights[0].directionZ);
        modelLightStruct_setDiffuseColor(gSkySunLight, gSkyState[offset + 0x78], gSkyState[offset + 0x79],
                                         gSkyState[offset + 0x7a], 0xff);
    }
    if (gSkyMoonLight != NULL)
    {
        offset = slot * 0xa4;
        sky = (SkyState*)(gSkyState + offset);
        modelLightStruct_setDirection(gSkyMoonLight, sky->lights[0].moonDirectionX,
                                      sky->lights[0].moonDirectionY,
                                      sky->lights[0].moonDirectionZ);
        modelLightStruct_setDiffuseColor(gSkyMoonLight, gSkyState[offset + 0x80], gSkyState[offset + 0x81],
                                         gSkyState[offset + 0x82], 0xff);
    }
    lightSetColor(0, gSkyState[slot * 0xa4 + 0x88], gSkyState[slot * 0xa4 + 0x89], gSkyState[slot * 0xa4 + 0x8a]);
}

ModelLightStruct* skyGetMoonLight(void)
{
    return gSkyMoonLight;
}

ModelLightStruct* skyGetSunLight(void)
{
    return gSkySunLight;
}

void skySetLightSlot(int slot, f32 x, f32 y, f32 z, int red, int green, int blue, int moonIntensity,
                 int ambientIntensity, u8 blendAlpha)
{
    Vec dir;
    int moonR;
    int moonG;
    int moonB;
    int ambientR;
    int ambientG;
    int ambientB;
    u32 previousComponent;
    int ambientScale;
    int entryOffset;
    SkyState* skyEntry;
    f32 blend;
    int moonScale;
    SkyLight* previous;
    SkyLight* current;

    dir.x = -x;
    dir.y = -y;
    dir.z = -z;
    if (slot == 2)
    {
        previous = &((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->previousLightIndex];
        current = &((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->currentLightIndex];
        dir.x = previous->directionX +
                 ((SkyState*)gSkyState)->lightBlendFactor * (current->directionX - previous->directionX);
        dir.y = previous->directionY +
                 ((SkyState*)gSkyState)->lightBlendFactor * (current->directionY - previous->directionY);
        dir.z = previous->directionZ +
                 ((SkyState*)gSkyState)->lightBlendFactor * (current->directionZ - previous->directionZ);
        blend = ((SkyState*)gSkyState)->lightBlendFactor;
        previousComponent = previous->sunColorR;
        red = (int)(blend * ((f32)current->sunColorR - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->sunColorG;
        green = (int)(blend * ((f32)current->sunColorG - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->sunColorB;
        blue = (int)(blend * ((f32)current->sunColorB - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->moonColorR;
        moonR = (int)(blend * ((f32)current->moonColorR - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->moonColorG;
        moonG = (int)(blend * ((f32)current->moonColorG - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->moonColorB;
        moonB = (int)(blend * ((f32)current->moonColorB - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->ambientR;
        ambientR = (int)(blend * ((f32)current->ambientR - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->ambientG;
        ambientG = (int)(blend * ((f32)current->ambientG - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->ambientB;
        ambientB = (int)(blend * ((f32)current->ambientB - (f32)previousComponent) + (f32)previousComponent);
        previousComponent = previous->blendAlpha;
        blendAlpha = blend * ((f32)current->blendAlpha - (f32)previousComponent) + (f32)previousComponent;
    }
    else
    {
        if (((SkyState*)gSkyState)->lights[slot].flags.unused80 != 0)
        {
            dir.x = (-1.0f);
            dir.y = (-1.0f);
            dir.z = (-1.0f);
            PSVECNormalize(&dir, &dir);
            PSMTXMultVecSR((MtxPtr)Camera_GetInverseViewMatrix(), &dir, &dir);
        }
        entryOffset = slot * 0xa4;
        if (((SkyState*)gSkyState)->lights[slot].flags.active != 0)
        {
            skyEntry = (SkyState*)(gSkyState + entryOffset);
            dir.x = skyEntry->lights[0].overrideDirectionX;
            dir.y = skyEntry->lights[0].overrideDirectionY;
            dir.z = skyEntry->lights[0].overrideDirectionZ;
            red = skyEntry->lights[0].overrideSunColorR;
            green = skyEntry->lights[0].overrideSunColorG;
            blue = skyEntry->lights[0].overrideSunColorB;
            moonR = skyEntry->lights[0].overrideMoonColorR;
            moonG = skyEntry->lights[0].overrideMoonColorG;
            moonB = skyEntry->lights[0].overrideMoonColorB;
            ambientR = skyEntry->lights[0].overrideAmbientR;
            ambientG = skyEntry->lights[0].overrideAmbientG;
            ambientB = skyEntry->lights[0].overrideAmbientB;
            blendAlpha = 0xff;
        }
        else
        {
            moonScale = moonIntensity + 1;
            moonR = red * moonScale >> 8;
            moonG = green * moonScale >> 8;
            moonB = blue * moonScale >> 8;
            ambientScale = ambientIntensity + 1;
            ambientR = red * ambientScale >> 8;
            ambientG = green * ambientScale >> 8;
            ambientB = blue * ambientScale >> 8;
        }
    }
    ((SkyLight*)(gSkyState + 0x20))[slot].directionX = dir.x;
    ((SkyLight*)(gSkyState + 0x20))[slot].directionY = dir.y;
    ((SkyLight*)(gSkyState + 0x20))[slot].directionZ = dir.z;
    gSkyState[slot * 0xa4 + 0x78] = red;
    gSkyState[slot * 0xa4 + 0x79] = green;
    gSkyState[slot * 0xa4 + 0x7a] = blue;
    ((SkyLight*)(gSkyState + 0x20))[slot].moonDirectionX = -dir.x;
    ((SkyLight*)(gSkyState + 0x20))[slot].moonDirectionY = -dir.y;
    ((SkyLight*)(gSkyState + 0x20))[slot].moonDirectionZ = -dir.z;
    gSkyState[slot * 0xa4 + 0x80] = (u8)(moonR * (colorScale + 1) >> 8);
    gSkyState[slot * 0xa4 + 0x81] = (u8)(moonG * (colorScale + 1) >> 8);
    gSkyState[slot * 0xa4 + 0x82] = (u8)(moonB * (colorScale + 1) >> 8);
    gSkyState[slot * 0xa4 + 0x88] = ambientR;
    gSkyState[slot * 0xa4 + 0x89] = ambientG;
    gSkyState[slot * 0xa4 + 0x8a] = ambientB;
    gSkyState[slot * 0xa4 + 0xc0] = blendAlpha;
}

const f32 gSkySecondsPerDay[1] = {86400.0f};

void skyUpdateLightingFromTimeOfDay(void)
{
    int curveSegment;
    int red;
    int green;
    f32* blendAlphaCurve;
    f32* moonIntensityCurve;
    f32* ambientIntensityCurve;
    int greenCurveOffset;
    int blueCurveOffset;
    int slotIndex;
    int lightSlotOffset;
    f32* lightingData;
    int rawR;
    int blue;
    int rawG;
    int ambientIntensity;
    int moonIntensity;
    u8 blendAlpha;
    f32 normalizedTime;
    f32 blend;
    f32 timeOfDay;
    SkyState* blendState;
    f32 zero;
    f32 segmentFraction;
    f32 dayStart;

    lightingData = gSkySunDirection;
    if (gSkyState == NULL)
    {
        for (slotIndex = 0; slotIndex < 3; slotIndex++)
        {
            skySetLightSlot(slotIndex, lightingData[0], lightingData[1], lightingData[2], 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff);
        }
    }
    else
    {
        normalizedTime = (((SkyState*)gSkyState)->timeOfDay / gSkySecondsPerDay[0] < 0.0f)
                             ? 0.0f
                             : ((((SkyState*)gSkyState)->timeOfDay / gSkySecondsPerDay[0] > 1.0f)
                                    ? 1.0f
                                    : ((SkyState*)gSkyState)->timeOfDay / gSkySecondsPerDay[0]);
        if (normalizedTime <= 0.25f)
        {
            segmentFraction = normalizedTime / 0.25f;
            curveSegment = 0;
        }
        else if (normalizedTime <= 0.5f)
        {
            segmentFraction = (normalizedTime - 0.25f) / 0.25f;
            curveSegment = 1;
        }
        else if (normalizedTime <= 0.75f)
        {
            segmentFraction = (normalizedTime - 0.5f) / 0.25f;
            curveSegment = 2;
        }
        else
        {
            segmentFraction = (normalizedTime - 0.75f) / 0.25f;
            curveSegment = 3;
        }
        for (slotIndex = 0; slotIndex < 2; slotIndex++)
        {
            blendAlphaCurve = &((f32*)((u8*)lightingData + 0x40))[curveSegment];
            moonIntensityCurve = &((f32*)((u8*)lightingData + 0x18))[curveSegment];
            ambientIntensityCurve = &((f32*)((u8*)lightingData + 0x2c))[curveSegment];
            greenCurveOffset = (curveSegment + 7) * 4;
            blueCurveOffset = (curveSegment + 0xe) * 4;
            zero = 0.0f;
            dayStart = 18000.0f;
            lightSlotOffset = 0xa4 * slotIndex;
            if (((SkyState*)gSkyState)->lights[slotIndex].flags.unused80 != 0)
            {
                blendAlpha = 0xc8;
                moonIntensity = 0;
                ambientIntensity = 0x60;
            }
            else
            {
                blendAlpha = (int)Curve_EvalLinear(blendAlphaCurve, segmentFraction, 0);
                moonIntensity = Curve_EvalLinear(moonIntensityCurve, segmentFraction, 0);
                ambientIntensity = Curve_EvalLinear(ambientIntensityCurve, segmentFraction, 0);
            }
            rawR =
                Curve_EvalCatmullRom(gSkyState + lightSlotOffset + curveSegment * 4 + 0x20, segmentFraction, 0);
            rawG = Curve_EvalCatmullRom(gSkyState + lightSlotOffset + greenCurveOffset + 0x20, segmentFraction, 0);
            blue = Curve_EvalCatmullRom(gSkyState + lightSlotOffset + blueCurveOffset + 0x20, segmentFraction, 0);
            blendState = (SkyState*)(gSkyState + lightSlotOffset);
            blend = blendState->lights[0].blendFactor;
            if (blend != zero)
            {
                rawR = (int)(blend * ((f32)blendState->lights[0].blendTargetR - rawR) + rawR);
                rawG = (int)(blend * ((f32)blendState->lights[0].blendTargetG - rawG) + rawG);
                blue = (int)(blend * ((f32)blendState->lights[0].blendTargetB - blue) + blue);
            }
            if (rawR < 0)
            {
                red = 0;
            }
            else if (rawR > 0xff)
            {
                red = 0xff;
            }
            else
            {
                red = rawR;
            }
            if (rawG < 0)
            {
                green = 0;
            }
            else if (rawG > 0xff)
            {
                green = 0xff;
            }
            else
            {
                green = rawG;
            }
            if (blue < 0)
            {
                blue = 0;
            }
            else if (blue > 0xff)
            {
                blue = 0xff;
            }
            if (slotIndex == 0)
            {
                gSkyCurrentTextureColor.r = red;
                gSkyCurrentTextureColor.g = green;
                gSkyCurrentTextureColor.b = blue;
            }
            timeOfDay = ((SkyState*)gSkyState)->timeOfDay;
            if (timeOfDay >= dayStart && timeOfDay <= 75600.0f)
            {
                skySetLightSlot(slotIndex, lightingData[0], lightingData[1], lightingData[2], red, green, blue,
                                moonIntensity, ambientIntensity, blendAlpha);
            }
            else
            {
                skySetLightSlot(slotIndex, -lightingData[3], lightingData[4], -lightingData[5], red, green, blue,
                                moonIntensity, ambientIntensity, blendAlpha);
            }
        }
        skySetLightSlot(2, 0.0f, 0.0f, 0.0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    }
}

void skyUpdateShadowLightDirection(void)
{
    f32 dot;
    f32 len;
    f32 time;

    if (gSkyState != NULL)
    {
        dot = gSkySunDirection[2] * gSkySunDirection[2] +
              (gSkySunDirection[0] * gSkySunDirection[0] + gSkySunDirection[1] * gSkySunDirection[1]);
        if (dot != 0.0f)
        {
            len = sqrtf(dot);
        }
        else
        {
            len = 1.0f;
        }
        *gSkySunDirection = *gSkySunDirection / len;
        gSkySunDirection[1] = gSkySunDirection[1] / len;
        gSkySunDirection[2] = gSkySunDirection[2] / len;
        dot = gSkyMoonDirection[2] * gSkyMoonDirection[2] +
              (gSkyMoonDirection[0] * gSkyMoonDirection[0] + gSkyMoonDirection[1] * gSkyMoonDirection[1]);
        if (dot != 0.0f)
        {
            len = sqrtf(dot);
        }
        else
        {
            len = 1.0f;
        }
        *gSkyMoonDirection = *gSkyMoonDirection / len;
        gSkyMoonDirection[1] = gSkyMoonDirection[1] / len;
        gSkyMoonDirection[2] = gSkyMoonDirection[2] / len;
        time = ((SkyState*)gSkyState)->timeOfDay;
        if (time >= 18000.0f && time <= 75600.0f)
        {
            if (gSkyOverrideLightDirectionEnabled != 0)
            {
                shadowSetLightDirection(gSkyOverrideLightDirection[0], gSkyOverrideLightDirection[1],
                               gSkyOverrideLightDirection[2], gSkyOverrideLightIntensity);
            }
            else
            {
                shadowSetLightDirection(*gSkySunDirection, gSkySunDirection[1], gSkySunDirection[2], 100);
            }
            (*gCloudActionInterface)->func08Nop(*gSkySunDirection, gSkySunDirection[1], gSkySunDirection[2], 1);
        }
        else
        {
            if (gSkyOverrideLightDirectionEnabled != 0)
            {
                shadowSetLightDirection(gSkyOverrideLightDirection[0], gSkyOverrideLightDirection[1],
                               gSkyOverrideLightDirection[2], gSkyOverrideLightIntensity);
            }
            else
            {
                shadowSetLightDirection(-(*gSkyMoonDirection), gSkyMoonDirection[1], -gSkyMoonDirection[2], 100);
            }
            (*gCloudActionInterface)->func08Nop(-(*gSkyMoonDirection), gSkyMoonDirection[1], -gSkyMoonDirection[2], 0);
        }
    }
}

void renderSunAndMoon(int a, int b, int c, int d, int visible)
{
    SkyRotQ q1;
    f32 moonTC;
    f32 vec[3];
    Vec sunDir;
    Vec moonDir;
    int v;
    Camera* cam;
    f32 far;
    f32 yaw;
    f32 riseScale;
    f32 sunT;
    f32 moonT;
    SkyRotQ q2;
    u8 vis;
    ObjModel* model;
    SkyState* sky;

    cam = Camera_GetCurrent();
    sunDir = gSkyBaseSunDirection;
    moonDir = gSkyBaseMoonDirection;
    v = 0;
    q1.x = 0.0f;
    q1.y = 0.0f;
    q1.z = 0.0f;
    q1.w = 1.0f;
    q1.rz = 0;
    q1.ry = 0;
    q1.rx = 0;
    q2.x = 0.0f;
    q2.y = 0.0f;
    q2.z = 0.0f;
    q2.w = 1.0f;
    q2.rz = 0;
    q2.ry = 0;
    q2.rx = 0;
    (*gSkyInterface)->getTransitionTimer(&v);
    if (cam != NULL && gSkyState != NULL)
    {
        far = Camera_GetFarPlane();
        Camera_SetFarPlane(15000.0f, 0);
        Camera_RebuildProjectionMatrix();
        sky = (SkyState*)gSkyState;
        sunT = (sky->timeOfDay - 18000.0f) / 57600.0f;
        if (sunT < 0.0f)
        {
            sunT = 0.0f;
        }
        else if (sunT > 1.0f)
        {
            sunT = 1.0f;
        }
        if (sunT < 0.1f)
        {
            if (sunT < 0.0f)
            {
                gSkySunAlpha = 0;
            }
            else
            {
                *(s16*)&gSkySunAlpha = (2550.0f * sunT);
            }
        }
        else
        {
            if (sunT > 0.9f)
            {
                if (sunT > 1.0f)
                {
                    gSkySunAlpha = 0;
                }
                else
                {
                    *(s16*)&gSkySunAlpha =
                        (2550.0f * (0.1f - (sunT - 0.9f)));
                }
            }
            else
            {
                gSkySunAlpha = 0xff;
            }
        }
        sunT *= 32676.0f;
        riseScale = (sky->timeOfDay - 18000.0f) / 28800.0f;
        if (riseScale < 0.0f)
        {
            riseScale = 0.0f;
        }
        else if (riseScale > 1.0f)
        {
            riseScale = 1.0f - (riseScale - 1.0f);
        }
        riseScale = -(0.55f * riseScale - 1.0f);
        vec[0] = 2.0f * sunDir.x;
        vec[1] = 2.0f * sunDir.y;
        vec[2] = 2.0f * sunDir.z;
        yaw = sky->sunYaw;
        q1.rx = sunT;
        vecRotateZXY(&q1.rx, vec);
        q1.w = 1.0f;
        q1.rz = yaw;
        q1.ry = 0;
        q1.rx = 0;
        vecRotateZXY(&q1.rx, vec);
        gSkySunDirection[0] = vec[0];
        gSkySunDirection[1] = vec[1];
        gSkySunDirection[2] = vec[2];
        gSkySunObject->anim.localPosX = cam->worldX + (f32)(s16)(int)vec[0];
        gSkySunObject->anim.localPosY = cam->worldY + (f32)(s16)(int)vec[1];
        gSkySunObject->anim.localPosZ = cam->worldZ + (f32)(s16)(int)vec[2];
        gSkySunObject->anim.rootMotionScale = 400.0f * riseScale;
        *(s16*)gSkySunObject = 0x10000 - cam->yaw;
        gSkySunObject->anim.rotY = cam->pitch;
        gSkySunObject->anim.rotZ = 0;
        gSkySunObject->anim.renderAlpha = *(s16*)&gSkySunAlpha;
        moonT = ((SkyState*)gSkyState)->timeOfDay;
        if (moonT >= 75600.0f)
        {
            moonT -= 75600.0f;
        }
        else
        {
            moonT += 10800.0f;
        }
        moonTC = moonT / 28800.0f;
        if (moonTC < 0.0f)
        {
            moonTC = 0.0f;
        }
        else if (moonTC > 1.0f)
        {
            moonTC = 1.0f;
        }
        if (moonTC < 0.1f)
        {
            if (moonTC < 0.0f)
            {
                gSkyMoonAlpha = 0;
            }
            else
            {
                *(s16*)&gSkyMoonAlpha = (2550.0f * moonTC);
            }
        }
        else
        {
            if (moonTC > 0.9f)
            {
                if (moonTC > 1.0f)
                {
                    gSkyMoonAlpha = 0;
                }
                else
                {
                    *(s16*)&gSkyMoonAlpha =
                        (2550.0f * (0.1f - (moonTC - 0.9f)));
                }
            }
            else
            {
                gSkyMoonAlpha = 0xff;
            }
        }
        moonTC *= 32676.0f;
        riseScale = moonT / 14400.0f;
        if (riseScale < 0.0f)
        {
            riseScale = 0.0f;
        }
        else if (riseScale > 1.0f)
        {
            riseScale = 1.0f - (riseScale - 1.0f);
        }
        riseScale = -(0.55f * riseScale - 1.0f);
        vec[0] = 2.0f * moonDir.x;
        vec[1] = 2.0f * moonDir.y;
        vec[2] = 2.0f * moonDir.z;
        q2.rx = moonTC;
        vecRotateZXY(&q2.rx, vec);
        q2.w = 1.0f;
        q2.rz = yaw;
        q2.ry = 0;
        q2.rx = 0;
        vecRotateZXY(&q2.rx, vec);
        gSkyMoonDirection[0] = vec[0];
        gSkyMoonDirection[1] = vec[1];
        gSkyMoonDirection[2] = vec[2];
        gSkyMoonObject->anim.localPosX = cam->worldX + (f32)(s16)(int)vec[0];
        gSkyMoonObject->anim.localPosY = cam->worldY + (f32)(s16)(int)vec[1];
        gSkyMoonObject->anim.localPosZ = cam->worldZ + (f32)(s16)(int)vec[2];
        gSkyMoonObject->anim.rootMotionScale = 400.0f * riseScale;
        gSkyMoonObject->anim.rotX = 0x10000 - cam->yaw;
        gSkyMoonObject->anim.rotY = cam->pitch;
        vis = 0;
        gSkyMoonObject->anim.rotZ = 0;
        gSkyMoonObject->anim.renderAlpha = *(s16*)&gSkyMoonAlpha;
        if (gSkySunObject->anim.renderAlpha != 0)
        {
            if (gSkyState != NULL)
            {
                vis = ((SkyState*)gSkyState)->lights[2].flags.unused80;
            }
            if (vis == 0 && (u8)visible != 0)
            {
                model = Obj_GetActiveModel(gSkySunObject);
                model->bufferFlags &= ~8;
                objRender(a, b, c, d, gSkySunObject, 1);
            }
        }
        if (gSkyMoonObject->anim.renderAlpha != 0)
        {
            if (gSkyState != NULL)
            {
                vis = ((SkyState*)gSkyState)->lights[2].flags.unused80;
            }
            else
            {
                vis = 0;
            }
            if (vis == 0 && (u8)visible != 0)
            {
                model = Obj_GetActiveModel(gSkyMoonObject);
                model->bufferFlags &= ~8;
                objRender(a, b, c, d, gSkyMoonObject, 1);
            }
        }
        Camera_SetFarPlane(far, 0);
        Camera_RebuildProjectionMatrix();
    }
}

void skyRenderTimeOfDayBackdrop(void)
{
    int* sky;
    int texA;
    int texB;
    Texture* texC;
    Camera* cam;
    GameObject* player;
    int cell;
    u8* tbl;
    u8* channel;
    int idxA;
    int idxB;
    int phase;
    int gradA;
    int gradB;
    u32 texHeight;
    u32 screenRes;
    int texHandle;
    f32 u;
    f32 frac;
    f32 t;
    f32 tc;
    f32 sinProd;
    f32 texHeightF;
    f32 angle;
    f32 blend;
    f32 v;
    f32 ang0;
    GXColor fogColor;

    fogColor = *(GXColor*)&lbl_803E8458;
    if (gSkyState != NULL)
    {
        if ((player = Obj_GetPlayerObject()) != NULL &&
            (((cell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ)) ==
              0x30) ||
             cell == 0x2b))
        {
            return;
        }
        sky = *(int**)&gSkyState;
        frac = ((SkyTimeBlend*)sky)->time / gSkySecondsPerDay[0];
        t = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
        u = 0.0f;
        if (t >= u && t < 0.125f)
        {
            u = t / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 0;
        }
        else if (t >= 0.125f && t < 0.25f)
        {
            u = (t - 0.125f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 1;
        }
        else if (t >= 0.25f && t < 0.375f)
        {
            u = (t - 0.25f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 2;
        }
        else if (t >= 0.375f && t < 0.5f)
        {
            u = (t - 0.375f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 3;
        }
        else if (t >= 0.5f && t < 0.625f)
        {
            u = (t - 0.5f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 4;
        }
        else if (t >= 0.625f && t < 0.75f)
        {
            u = (t - 0.625f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 5;
        }
        else if (t >= 0.75f && t < 0.875f)
        {
            u = (t - 0.75f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 6;
        }
        else if (t >= 0.875f && t <= 1.0f)
        {
            u = (t - 0.875f) / 0.125f;
            ((SkyTimeBlend*)sky)->phase = 7;
        }
        tc = (u < 0.0f) ? 0.0f : ((u > 1.0f) ? 1.0f : u);
        sky = *(int**)&gSkyState;
        phase = ((SkyTimeBlend*)sky)->phase;
        if (phase != ((SkyTimeBlend*)sky)->prevPhase)
        {
            texA = sky[phase + 0x87];
            texB = sky[(phase + 1) % 8 + 0x87];
            if (((SkyTimeBlend*)sky)->texAId != texA)
            {
                textureFree((Texture*)((void*)sky[0]));
                *(void**)gSkyState = textureLoadAsset(texA);
                ((SkyTimeBlend*)gSkyState)->texAId = texA;
            }
            sky = *(int**)&gSkyState;
            if (((SkyTimeBlend*)sky)->texBId != texB)
            {
                textureFree((Texture*)((void*)sky[1]));
                ((SkyTimeBlend*)gSkyState)->texB = textureLoadAsset(texB);
                ((SkyTimeBlend*)gSkyState)->texBId = texB;
            }
            ((SkyTimeBlend*)gSkyState)->prevPhase = (s8)((SkyTimeBlend*)gSkyState)->phase;
        }
        blendTextures(((SkyTimeBlend*)gSkyState)->texB, ((SkyTimeBlend*)gSkyState)->texA, tc,
                      (void*)(*(int**)&gSkyState)[((SkyTimeBlend*)gSkyState)->texSel + 2]);
        ((SkyState*)gSkyState)->fadeFlags.fadePending = 1;
        sky = *(int**)&gSkyState;
        blend = ((SkyTimeBlend*)sky)->blend;
        if (blend)
        {
            texHandle = sky[((SkyTimeBlend*)sky)->texSel + 2];
            blendTextures((void*)sky[4], (void*)texHandle, blend, (void*)texHandle);
        }
        sky = *(int**)&gSkyState;
        idxA = (s16)(sky[((SkyTimeBlend*)sky)->phase + 0x87] - 0xc38) * 6;
        tbl = gSkyColorBlendTable;
        gradA = tbl[idxA];
        idxB = (s16)(sky[(((SkyTimeBlend*)sky)->phase + 1) % 8 + 0x87] - 0xc38) * 6;
        gradB = tbl[idxB];
        gSkyCurrentLightColor.r = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        channel = tbl + 1;
        gradA = channel[idxA];
        gradB = channel[idxB];
        gSkyCurrentLightColor.g = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        channel = tbl + 2;
        gradA = channel[idxA];
        gradB = channel[idxB];
        gSkyCurrentLightColor.b = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        channel = tbl + 3;
        gradA = channel[idxA];
        gradB = channel[idxB];
        gSkyCurrentAmbientColor.r = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        channel = tbl + 4;
        gradA = channel[idxA];
        gradB = channel[idxB];
        gSkyCurrentAmbientColor.g = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        channel = tbl + 5;
        gradA = channel[idxA];
        gradB = channel[idxB];
        gSkyCurrentAmbientColor.b = (u8)(int)(tc * (f32)(gradB - gradA) + (f32)(u32)gradA);
        texC = (Texture*)sky[((SkyTimeBlend*)sky)->texSel + 2];
        cam = Camera_GetCurrent();
        frac = Camera_GetFovY();
        frac = frac / 2.0f;
        texHeightF = (f32)(u32)texC->height;
        sinProd = texHeightF * frac / 180.0f;
        sinProd *= 3.0f;
        sinProd *= mathCosf(3.1415927f * (f32)-cam->worldRoll / 32768.0f);
        ang0 = texHeightF / 2.0f - 6.0f - 3.0f * (texHeightF * cam->worldPitch) / 32768.0f;
        angle = ang0 + sinProd;
        angle *= 32.0f;
        (*gSky2Interface)->applyTextColor(0);
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
        selectTexture(texC, 0);
        gxSetOpaqueNoZWriteMode();
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_TEXC, GX_CC_C1, GX_CC_A1, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
        GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetNumIndStages(0);
        GXSetNumChans(0);
        GXSetNumTexGens(1);
        GXSetNumTevStages(1);
        screenRes = getScreenResolution();
        sinProd *= 2.0f;
        texHeight = texC->height;
        v = angle / (32.0f * (f32)texHeight);
        drawOrthoTexturedQuad(0, 0, (screenRes & 0xffff) << 2, (screenRes >> 16) << 2, 0.0f, v,
                           1.0f, v - sinProd / (f32)texHeight, -0x18f);
    }
}

int skyGetVisibility(int slot)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky != NULL)
    {
        return sky->lights[slot].flags.visibility;
    }
    return 0;
}

void skyTimeToDayHourMinute(f32 time, s16* days, s16* hours, s16* minutes)
{
    s32 remaining;

    remaining = time;
    *days = remaining / 0x34bc0;
    remaining -= *days * 0x34bc0;
    *hours = remaining / 0xe10;
    remaining -= *hours * 0xe10;
    *minutes = remaining / 0x3c;
}

int skyReservedReturnZeroA(void)
{
    return 0x0;
}

int getSunPos(f32* outTime)
{
    f32 time;

    if (gSkyState == NULL)
    {
        if (outTime != NULL)
        {
            *outTime = 0.0f;
        }
        return 0;
    }

    time = ((SkyState*)gSkyState)->timeOfDay;
    if (time >= 75600.0f || time < 18000.0f)
    {
        if (outTime != NULL)
        {
            if (time >= 75600.0f)
            {
                *outTime = 18000.0f + (time - 75600.0f);
            }
            else
            {
                *outTime = 18000.0f - time;
            }
        }
        return 1;
    }

    if (outTime != NULL)
    {
        *outTime = 75600.0f - time;
    }
    return 0;
}

void skyGetTimer(int* outTimer)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky == NULL)
    {
        *outTimer = 0;
        return;
    }
    *outTimer = sky->timer;
}

void skyReservedNopA(void)
{
}

void skyGetClockTime(f32* time)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky == NULL)
    {
        *time = 0.0f;
    }
    else
    {
        *time = sky->clockTime;
    }
}

void pDll_Sky_setTimeOfDay_nop(void)
{
}

void getTimeOfDay(f32* time)
{
    SkyState* sky;

    sky = (SkyState*)gSkyState;
    if (sky == NULL)
    {
        *time = 0.0f;
        return;
    }
    *time = sky->timeOfDay;
}

void renderSky(int a, int b, int c, int d, int visible)
{
    if (gSkySunObject != NULL && gSkyMoonObject != NULL)
    {
        renderSunAndMoon(a, b, c, d, visible);
    }
    skyUpdateShadowLightDirection();
    skyUpdateLightingFromTimeOfDay();
}

void skyUpdateTimeOfDay(void)
{
    u8* env;
    f32 time;
    int timer;
    int i;
    int count;
    f32 val;

    time = 0.0f;
    env = (u8*)saveGameGetEnvState();
    if (gSkyState == NULL || gSkyObjectsInitialized == 0)
    {
        return;
    }
    else
    {
        {
            ((SkyState*)gSkyState)->timeOfDay += ((SkyState*)gSkyState)->timeOfDayRate * timeDelta;
            if (((SkyState*)gSkyState)->timeOfDay >= gSkySecondsPerDay[0])
            {
                ((SkyState*)gSkyState)->timeOfDay = ((SkyState*)gSkyState)->timeOfDay - gSkySecondsPerDay[0];
            }
            else if (((SkyState*)gSkyState)->timeOfDay < 0.0f)
            {
                ((SkyState*)gSkyState)->timeOfDay = ((SkyState*)gSkyState)->timeOfDay + gSkySecondsPerDay[0];
            }
            if (getSunPos(&time) != 0)
            {
                if (((SkyState*)gSkyState)->transitionLatch == 0)
                {
                    ((SkyState*)gSkyState)->transitionLatch = 1;
                }
            }
            else
            {
                if (((SkyState*)gSkyState)->transitionLatch != 0)
                {
                    timer = ((SkyState*)gSkyState)->timer + 1;
                    ((SkyState*)gSkyState)->timer = timer;
                    if (timer > 0x1e)
                    {
                        ((SkyState*)gSkyState)->timer = 0;
                    }
                    ((SkyState*)gSkyState)->transitionLatch = 0;
                }
            }
            if (Obj_GetPlayerObject() != NULL)
            {
                *(f32*)env = ((SkyState*)gSkyState)->timeOfDay;
            }
            i = 0;
            for (count = 2; count != 0; count--)
            {
                ((SkyState*)gSkyState)->lights[i].blendFactor -=
                    ((SkyState*)gSkyState)->lights[i].blendRate * timeDelta;
                val = ((SkyState*)gSkyState)->lights[i].blendFactor;
                ((SkyState*)gSkyState)->lights[i].blendFactor =
                    (val < 0.0f) ? 0.0f : ((val > 1.0f) ? 1.0f : val);
                ((SkyState*)gSkyState)->lights[i].unk9C -= 0.008333334f * timeDelta;
                val = ((SkyState*)gSkyState)->lights[i].unk9C;
                ((SkyState*)gSkyState)->lights[i].unk9C =
                    (val < 0.0f) ? 0.0f : ((val > 1.0f) ? 1.0f : val);
                i++;
            }
            ((SkyState*)gSkyState)->fadeFactor -= ((SkyState*)gSkyState)->fadeRate * timeDelta;
            val = ((SkyState*)gSkyState)->fadeFactor;
            ((SkyState*)gSkyState)->fadeFactor =
                (val < 0.0f) ? 0.0f : ((val > 1.0f) ? 1.0f : val);
            ((SkyState*)gSkyState)->lightBlendFactor += ((SkyState*)gSkyState)->lightBlendRate * timeDelta;
            val = ((SkyState*)gSkyState)->lightBlendFactor;
            ((SkyState*)gSkyState)->lightBlendFactor =
                (val < 0.0f) ? 0.0f : ((val > 1.0f) ? 1.0f : val);
        }
    }
}

void skyLoadLights(void)
{
    u8 done = 0;

    while (getLoadedFileFlags(0) != 0)
    {
        padUpdate();
        checkReset();
        if (done)
        {
            waitNextFrame();
        }
        loadDataFiles();
        dvdCheckError();
        if (done)
        {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (gDvdErrorPauseActive != 0)
        {
            done = 1;
        }
    }
    gSkyOverrideLightDirectionEnabled = 0;
    gSkyOverrideLightColorEnabled = 0;
    gSkyOverrideLightColor.r = 0xff;
    gSkyOverrideLightColor.g = 0xff;
    gSkyOverrideLightColor.b = 0xff;
    if (gSkySunLight == NULL)
    {
        gSkySunLight = objCreateLight(0, 1);
        if (gSkySunLight != NULL)
        {
            modelLightStruct_setLightKind(gSkySunLight, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setDirection(gSkySunLight, 0.0f, -1.0f, 0.0f);
            modelLightStruct_setDiffuseColor(gSkySunLight, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setSpecularColor(gSkySunLight, 0xff, 0xff, 0xff, 0xff);
        }
        gSkyMoonLight = objCreateLight(0, 1);
        if (gSkyMoonLight != NULL)
        {
            modelLightStruct_setLightKind(gSkyMoonLight, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setDirection(gSkyMoonLight, 0.0f, 1.0f, 0.0f);
            modelLightStruct_setDiffuseColor(gSkyMoonLight, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setSpecularColor(gSkyMoonLight, 0xff, 0xff, 0xff, 0xff);
        }
    }
    skyResetState();
    skySetSlotFlag80(7, 0);
    skySetLightIndex(0, 0.0f);
    skyUpdateShadowLightDirection();
    skyUpdateLightingFromTimeOfDay();
    gSkySunDirection[0] = 0.0f;
    gSkySunDirection[1] = (-1.0f);
    gSkySunDirection[2] = 0.0f;
    gSkyMoonDirection[0] = 0.0f;
    gSkyMoonDirection[1] = (-1.0f);
    gSkyMoonDirection[2] = 0.0f;
    gSkySkyTexture = textureLoadAsset(SKY_TEXTURE_SKY);
}

void skyResetState(void)
{
    Texture* tex0;
    int i;
    int j;

    if (gSkyState != NULL)
    {
        if (gSkyState != NULL)
        {
            if (*(u8**)gSkyState != NULL)
            {
                textureFree((Texture*)(*(u8**)gSkyState));
            }
            if (((SkyState*)gSkyState)->handle != NULL)
            {
                textureFree((Texture*)(((SkyState*)gSkyState)->handle));
            }
            mm_free(((SkyState*)gSkyState)->texture0);
            mm_free(((SkyState*)gSkyState)->texture1);
            mm_free(gSkyState);
        }
        gSkyState = NULL;
    }
    gSkyState = mmAlloc(sizeof(SkyState), 0x17, 0);
    memset(gSkyState, 0, sizeof(SkyState));
    ((SkyState*)gSkyState)->unk250 = -1;
    ((SkyState*)gSkyState)->timer = randomGetRange(0, 0x1c);
    ((SkyState*)gSkyState)->unk252 = 0xc;
    ((SkyState*)gSkyState)->unk253 = 0;
    ((SkyState*)gSkyState)->timeOfDay = 43200.0f;
    ((SkyState*)gSkyState)->clockTime = 0xb4;
    ((SkyState*)gSkyState)->sunYaw = 10000.0f;
    ((SkyState*)gSkyState)->timeOfDayRate = (f32)((SkyState*)gSkyState)->clockTime / 60.0f;
    ((SkyState*)gSkyState)->skyTextureIds[0] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[1] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[2] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[3] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[4] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[5] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[6] = 0xc38;
    ((SkyState*)gSkyState)->skyTextureIds[7] = 0xc38;
    *(u8**)gSkyState = textureLoadAsset(((SkyState*)gSkyState)->skyTextureIds[0]);
    ((SkyState*)gSkyState)->handle = textureLoadAsset(((SkyState*)gSkyState)->skyTextureIds[1]);
    ((SkyState*)gSkyState)->textureId0 = 0xc38;
    ((SkyState*)gSkyState)->textureId1 = 0xc38;
    tex0 = (Texture*)*(u8**)gSkyState;
    ((SkyState*)gSkyState)->texture0 = textureAlloc(tex0->width, tex0->height, 6, 0, 0, 1, 0, 1, 1);
    ((SkyState*)gSkyState)->texture1 = textureAlloc(tex0->width, tex0->height, 6, 0, 0, 1, 0, 1, 1);
    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < 3; j++)
        {
            ((SkyState*)gSkyState)->lights[i].curves[j][0] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][1] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][2] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][3] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][4] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][5] = 255.0f;
            ((SkyState*)gSkyState)->lights[i].curves[j][6] = 255.0f;
        }
        ((SkyState*)gSkyState)->lights[i].blendTargetR = 0xff;
        ((SkyState*)gSkyState)->lights[i].blendTargetG = 0xff;
        ((SkyState*)gSkyState)->lights[i].blendTargetB = 0xff;
        ((SkyState*)gSkyState)->lights[i].sunColorR = 0xff;
        ((SkyState*)gSkyState)->lights[i].sunColorG = 0xff;
        ((SkyState*)gSkyState)->lights[i].sunColorB = 0xff;
        ((SkyState*)gSkyState)->lights[i].moonColorR = 0xff;
        ((SkyState*)gSkyState)->lights[i].moonColorG = 0xff;
        ((SkyState*)gSkyState)->lights[i].moonColorB = 0xff;
        ((SkyState*)gSkyState)->lights[i].ambientR = 0xff;
        ((SkyState*)gSkyState)->lights[i].ambientG = 0xff;
        ((SkyState*)gSkyState)->lights[i].ambientB = 0xff;
        ((SkyState*)gSkyState)->lights[i].directionX = 0.0f;
        ((SkyState*)gSkyState)->lights[i].directionY = (-1.0f);
        ((SkyState*)gSkyState)->lights[i].directionZ = 0.0f;
        ((SkyState*)gSkyState)->lights[i].moonDirectionX = 0.0f;
        ((SkyState*)gSkyState)->lights[i].moonDirectionY = (-1.0f);
        ((SkyState*)gSkyState)->lights[i].moonDirectionZ = 0.0f;
        ((SkyState*)gSkyState)->lights[i].flags.active = 0;
        ((SkyState*)gSkyState)->lights[i].overrideDirectionX = 0.2f;
        ((SkyState*)gSkyState)->lights[i].overrideDirectionY = 1.0f;
        ((SkyState*)gSkyState)->lights[i].overrideDirectionZ = 0.2f;
        ((SkyState*)gSkyState)->lights[i].overrideSunColorR = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideSunColorG = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideSunColorB = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideMoonColorR = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideMoonColorG = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideMoonColorB = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideAmbientR = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideAmbientG = 0xff;
        ((SkyState*)gSkyState)->lights[i].overrideAmbientB = 0xff;
        ((SkyState*)gSkyState)->lights[i].blendAlpha = 0x80;
    }
}

void skyUpdateEnvfxAct(int a, int b, u8* cfg)
{
    s16* envp;
    u8* env2;
    u8 mask;
    int iofs;
    int i;
    SkyState* slot;
    u32 cloudMode;
    int vis;
    int tmp;

    envp = (s16*)saveGameGetEnvState();
    if (cfg != NULL && ((int)((Sky2Config*)cfg)->flags & 2) != 0)
    {
        switch (((Sky2Config*)cfg)->cloudMode)
        {
        case 0:
        default:
            mask = 0xf;
            break;
        case 1:
            mask = 1;
            break;
        case 2:
            mask = 2;
            break;
        case 3:
            mask = 4;
            break;
        case 4:
            mask = 5;
            break;
        case 5:
            mask = 3;
            break;
        case 6:
            mask = 6;
            break;
        }
        for (i = 0, iofs = 0; i < 2; i++)
        {
            if ((mask & (1 << i)) != 0)
            {
                envp[2] = (s16)((Sky2Config*)cfg)->envfxActId - 1;
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[0] = (f32)(u32)((Sky2Config*)cfg)->redKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[1] = (f32)(u32)((Sky2Config*)cfg)->redKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[2] = (f32)(u32)((Sky2Config*)cfg)->redKeys[1];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[3] = (f32)(u32)((Sky2Config*)cfg)->redKeys[2];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[4] = (f32)(u32)((Sky2Config*)cfg)->redKeys[3];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[5] = (f32)(u32)((Sky2Config*)cfg)->redKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].redCurve[6] = (f32)(u32)((Sky2Config*)cfg)->redKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[0] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[1] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[2] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[1];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[3] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[2];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[4] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[3];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[5] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].greenCurve[6] = (f32)(u32)((Sky2Config*)cfg)->greenKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[0] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[1] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[2] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[1];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[3] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[2];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[4] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[3];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[5] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].blueCurve[6] = (f32)(u32)((Sky2Config*)cfg)->blueKeys[0];
                ((SkyState*)(gSkyState + iofs))->lights[0].blendFactor = 1.0f;
                if (((Sky2Config*)cfg)->fadeDurationA != 0)
                {
                    ((SkyState*)(gSkyState + iofs))->lights[0].blendRate =
                        1.0f / (10.0f * (f32)(u32)((Sky2Config*)cfg)->fadeDurationA);
                }
                else
                {
                    ((SkyState*)(gSkyState + iofs))->lights[0].blendRate = 1.0f;
                }
                slot = (SkyState*)(gSkyState + iofs);
                if (gSkyState == NULL)
                {
                    slot->lights[0].blendTargetB = 0xff;
                    slot->lights[0].blendTargetG = 0xff;
                    slot->lights[0].blendTargetR = 0xff;
                }
                else
                {
                    slot->lights[0].blendTargetR = slot->lights[0].sunColorR;
                    slot->lights[0].blendTargetG = ((SkyState*)(gSkyState + iofs))->lights[0].sunColorG;
                    slot->lights[0].blendTargetB = ((SkyState*)(gSkyState + iofs))->lights[0].sunColorB;
                }
                if (((Sky2Config*)cfg)->cloudBlendMode != 0)
                {
                    ((SkyLight*)(gSkyState + iofs + 0x20))->flags.cloud =
                        (((Sky2Config*)cfg)->cloudBlendMode & 1) + 1;
                }
                else
                {
                    ((SkyLight*)(gSkyState + iofs + 0x20))->flags.cloud = 0;
                }
            }
            envp++;
            iofs += 0xa4;
        }
        if (((Sky2Config*)cfg)->cloudBlendMode != 0)
        {
            skySetSlotFlag80(mask, (((Sky2Config*)cfg)->cloudBlendMode > 2 ? 1 : 0));
        }
        vis = ((Sky2Config*)cfg)->visibility;
        for (i = 0; i < 2; i++)
        {
            if ((mask & (1 << i)) != 0)
            {
                ((SkyState*)gSkyState)->lights[i].flags.visibility = vis;
            }
        }
        ((SkyState*)gSkyState)->lights[2].flags.visibility =
            ((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->currentLightIndex].flags.visibility;
        if ((((Sky2Config*)cfg)->flags & 1) == 0)
        {
            ((SkyState*)gSkyState)->skyTextureIds[0] = ((Sky2Config*)cfg)->skyTexId0 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[1] = ((Sky2Config*)cfg)->skyTexId1 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[2] = ((Sky2Config*)cfg)->skyTexId2 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[3] = ((Sky2Config*)cfg)->skyTexId3 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[4] = ((Sky2Config*)cfg)->skyTexId4 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[5] = ((Sky2Config*)cfg)->skyTexId5 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[6] = ((Sky2Config*)cfg)->skyTexId6 + 0xc38;
            ((SkyState*)gSkyState)->skyTextureIds[7] = ((Sky2Config*)cfg)->skyTexId7 + 0xc38;
            tmp = (int)((SkyState*)gSkyState)->texture1;
            ((SkyState*)gSkyState)->texture1 = (void*)*(int*)((u8*)&((SkyState*)gSkyState)->texture0 + ((SkyState*)gSkyState)->swapTexIndex * 4);
            *(int*)((u8*)&((SkyState*)gSkyState)->texture0 + ((SkyState*)gSkyState)->swapTexIndex * 4) = tmp;
            ((SkyState*)gSkyState)->unk250 = -1;
            if (((SkyState*)gSkyState)->fadeFlags.fadePending != 0)
            {
                ((SkyState*)gSkyState)->fadeFactor = 1.0f;
                if (((Sky2Config*)cfg)->fadeDurationA != 0)
                {
                    ((SkyState*)gSkyState)->fadeRate =
                        1.0f / (10.0f * (f32)(u32)((Sky2Config*)cfg)->fadeDurationA);
                }
                else
                {
                    ((SkyState*)gSkyState)->fadeRate = 1.0f;
                }
            }
            else
            {
                ((SkyState*)gSkyState)->fadeFactor = 0.0f;
            }
        }
        cloudMode = ((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->currentLightIndex].flags.cloud;
        if (cloudMode != 0)
        {
            setDrawCloudsAndLights(cloudMode - 1);
        }
        ((SkyState*)gSkyState)->lights[2].flags.unused80 =
            ((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->currentLightIndex].flags.unused80;
        ((SkyState*)gSkyState)->lights[2].flags.visibility =
            ((SkyState*)gSkyState)->lights[((SkyState*)gSkyState)->currentLightIndex].flags.visibility;
        env2 = (u8*)saveGameGetEnvState();
        if (getSaveGameLoadStatus() == 0)
        {
            for (i = 0; i < 2; i++)
            {
                if (((SkyState*)gSkyState)->lights[i].flags.unused80 != 0)
                {
                    env2[0x40] |= (2 << i);
                }
                else
                {
                    env2[0x40] &= ~(2 << i);
                }
            }
        }
    }
}

f32 gSkyOverrideLightDirection[4];
