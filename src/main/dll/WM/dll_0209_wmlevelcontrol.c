/*
 * WM_LevelControl (DLL 0x209) - Krazoa Palace level control.
 * TU = 0x801F3F18..0x801F48C0 (helper fn_801F3F18 + wmlevelcontrol_*,
 * reverse slot order ascending).
 *
 * init seeds the palace's game-bit progression from the map-event mode
 * (the 0xD1B..0xD1F spirit chain consumed by wmspiritplace and
 * friends); update shows the intro message while messageTimer runs,
 * drives the music game-bit latches, and calls the sky/light override
 * helper every frame. fn_801F3F18 cross-fades the palace's sky, light
 * and fog colors toward their spirit-restored values while the
 * gWmLevelControlBlendFactor blend factor (held at 1.0 during restore progress,
 * decaying 0.02/tick after) is up.
 */
#include "main/dll/WM/dll_0207_wmworm.h"
#include "main/gametext_show_api.h"
#include "main/textrender_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/audio/music_api.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/objseq_api.h"
#include "main/game_object.h"
#include "main/sky_api.h"
#include "main/object_descriptor.h"

#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/mapEventTypes.h"
#include "main/obj_group.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/frame_timing.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/WM/dll_020A_wmgeneralscales.h"

void WM_LevelControl_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void WM_LevelControl_update(GameObject* obj);
void WM_LevelControl_init(GameObject* obj);
void WM_LevelControl_release(void);
void WM_LevelControl_initialise(void);

ObjectDescriptor gWM_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_LevelControl_initialise,
    (ObjectDescriptorCallback)WM_LevelControl_release,
    0,
    (ObjectDescriptorCallback)WM_LevelControl_init,
    (ObjectDescriptorCallback)WM_LevelControl_update,
    (ObjectDescriptorCallback)WM_LevelControl_hitDetect,
    (ObjectDescriptorCallback)WM_LevelControl_render,
    (ObjectDescriptorCallback)WM_LevelControl_free,
    (ObjectDescriptorCallback)WM_LevelControl_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)WM_LevelControl_getExtraSize,
};

u8 gWmLevelControlSkyColorFrom[4] = {0x14, 0x20, 0x28, 0};
u8 gWmLevelControlSkyColorTo[4] = {0x12, 0x1E, 0x23, 0};
u8 gWmLevelControlLightColorFrom[4] = {0x7E, 0xAD, 0xB0, 0};
u8 gWmLevelControlLightColorTo[4] = {0xD2, 0xF1, 0xFF, 0};
u8 gWmLevelControlFogColorFrom[4] = {0x4E, 0x64, 0x6A, 0};
u8 gWmLevelControlFogColorTo[4] = {0x42, 0x56, 0x55, 0};

/* per-object extra state (getExtraSize == 0x1C) */
typedef struct WmLevelControlState
{
    f32 messageTimer; /* 0x00: intro-message frames left */
    s16 unk04;        /* 0x04: -1 at map-event mode 4, else unset */
    s16 unk06;        /* 0x06 */
    s16 unk08;        /* 0x08: 700 at mode 7, else unset */
    u8 unk0A;         /* 0x0A: 0x1E at mode 7, else unset */
    u8 unk0B;         /* 0x0B: cleared at init, never read */
    u8 pad0C[4];
    SCGameBitLatchState latch; /* 0x10: music-trigger latches */
    u8 latchesDisabled;        /* 0x14: set at mode 7; skips all latching */
    u8 pad15[3];
    u32 frameCounter; /* 0x18: frames since init */
} WmLevelControlState;

STATIC_ASSERT(offsetof(WmLevelControlState, unk08) == 0x08);
STATIC_ASSERT(offsetof(WmLevelControlState, latch) == 0x10);
STATIC_ASSERT(offsetof(WmLevelControlState, latchesDisabled) == 0x14);
STATIC_ASSERT(offsetof(WmLevelControlState, frameCounter) == 0x18);
STATIC_ASSERT(sizeof(WmLevelControlState) == 0x1C);

typedef struct
{
    f32 x, y, z;
} LightVec3;

typedef struct
{
    LightVec3 light;
    LightVec3 color;
    LightVec3 fog;
} LightVecSet;

typedef struct
{
    LightVec3 vecs[4];
} WmLevelControlSkyVecTable;

STATIC_ASSERT(sizeof(WmLevelControlSkyVecTable) == 0x30);

#define WMLEVELCONTROL_OBJGROUP 9

/* LightFoot Village map-event id (seeded from the palace spirit chain). */
#define WMLEVELCONTROL_MAP_LIGHTFOOT 0xe
const WmLevelControlSkyVecTable gWmLevelControlSkyVecTable = {{
    {-1.0f, -2.0f, -1.0f},
    {1.0f, -2.0f, 1.0f},
    {1.0f, -2.0f, 1.0f},
    {1.0f, -0.25f, 1.0f}
}}; /* sky light/color/fog vector table */
u8 gWmLevelControlBlendedLightColor[4];    /* blended light-color out-triplet */
u8 gWmLevelControlBlendedSkyColor[4];      /* blended sky-color out-triplet */
u8 gWmLevelControlBlendedFogColor[4];      /* blended fog-color out-triplet */
u8 gWmLevelControlBlendedLightIntensity;   /* blended light-intensity byte */
f32 gWmLevelControlBlendFactor;            /* current blend factor */
f32 gWmLevelControlBlendHold;              /* restore-blend hold flag */
void fn_801F3F18(GameObject* obj)
{
    LightVecSet L;
    f32 decay;
    const LightVec3* vecs;
    u8* fromColor;
    u8* toColor;

    vecs = gWmLevelControlSkyVecTable.vecs;
    L.fog = vecs[1];
    L.color = vecs[2];
    L.light = vecs[3];

    if ((u8)(*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == 7)
    {
        return;
    }

    setDrawLights(0);
    if ((u8)getSkyColorFn_80088e08(0) != 0)
    {
        skySetOverrideLightColorEnabled(0);
        skySetOverrideLightDirectionEnabled(0);
        skyFn_80089710(7, 0, 1);
        return;
    }

    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x88, 0xb7, 0xba);
    if ((obj->userData1 & 4) == 0)
    {
        skyFn_80089710(1, 1, 0);
        obj->userData1 |= 4;
    }
    else
    {
        skyFn_80089710(1, 1, 1);
    }

    /* hold the blend at full while spirit-restore progress is running,
       then decay it toward 0. */
    if (lightningGetRemainingFraction() > 0.0f)
    {
        gWmLevelControlBlendHold = 1.0f;
        gWmLevelControlBlendFactor = 1.0f;
    }
    decay = -(0.02f * timeDelta - gWmLevelControlBlendFactor);
    gWmLevelControlBlendFactor = decay;
    if (decay < 0.0f)
    {
        gWmLevelControlBlendFactor = 0.0f;
    }

    /* blend each color channel source->target by the blend factor. */
    fromColor = gWmLevelControlLightColorFrom;
    toColor = gWmLevelControlLightColorTo;
    gWmLevelControlBlendedLightColor[0] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[0] - fromColor[0]) + (f32)(s32)fromColor[0];
    gWmLevelControlBlendedLightColor[1] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[1] - fromColor[1]) + (f32)(s32)fromColor[1];
    gWmLevelControlBlendedLightColor[2] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[2] - fromColor[2]) + (f32)(s32)fromColor[2];
    skyFn_800895e0(1, gWmLevelControlBlendedLightColor[0], gWmLevelControlBlendedLightColor[1],
                   gWmLevelControlBlendedLightColor[2], 0x40, 0x40);

    fromColor = gWmLevelControlSkyColorFrom;
    toColor = gWmLevelControlSkyColorTo;
    gWmLevelControlBlendedSkyColor[0] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[0] - fromColor[0]) + (f32)(s32)fromColor[0];
    gWmLevelControlBlendedSkyColor[1] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[1] - fromColor[1]) + (f32)(s32)fromColor[1];
    gWmLevelControlBlendedSkyColor[2] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[2] - fromColor[2]) + (f32)(s32)fromColor[2];
    fn_80089510(1, gWmLevelControlBlendedSkyColor[0], gWmLevelControlBlendedSkyColor[1],
                gWmLevelControlBlendedSkyColor[2]);

    fromColor = gWmLevelControlFogColorFrom;
    toColor = gWmLevelControlFogColorTo;
    gWmLevelControlBlendedFogColor[0] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[0] - fromColor[0]) + (f32)(s32)fromColor[0];
    gWmLevelControlBlendedFogColor[1] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[1] - fromColor[1]) + (f32)(s32)fromColor[1];
    gWmLevelControlBlendedFogColor[2] =
        gWmLevelControlBlendFactor * (f32)((s32)toColor[2] - fromColor[2]) + (f32)(s32)fromColor[2];
    fn_80089578(1, gWmLevelControlBlendedFogColor[0], gWmLevelControlBlendedFogColor[1],
                gWmLevelControlBlendedFogColor[2]);

    gWmLevelControlBlendedLightIntensity =
        gWmLevelControlBlendFactor * 128.0f + 32.0f;
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(gWmLevelControlBlendFactor * (L.light.x - L.color.x) + L.color.x,
                                 gWmLevelControlBlendFactor * (L.light.y - L.color.y) + L.color.y,
                                 gWmLevelControlBlendFactor * (L.light.z - L.color.z) + L.color.z,
                                 100.0f);
    skyFn_800894a8(1, L.fog.x, L.fog.y, L.fog.z);
}

int WM_LevelControl_getExtraSize(void)
{
    return sizeof(WmLevelControlState);
}
int WM_LevelControl_getObjectTypeId(void)
{
    return 0x0;
}

void WM_LevelControl_free(int obj)
{
    ObjGroup_RemoveObject((u32)obj, WMLEVELCONTROL_OBJGROUP);
    Music_Trigger(MUSICTRIG_drako_3, 0);
    mainSetBits(GAMEBIT_WMRelated0A7F, 0);
    mainSetBits(GAMEBIT_KrazTest1Related0372, 1);
    mainSetBits(GAMEBIT_KrazTest1Related0390, 1);
}

void WM_LevelControl_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
}

void WM_LevelControl_hitDetect(void)
{
}

void WM_LevelControl_update(GameObject* obj)
{
    u32 mode6;
    int loadingDone;
    WmLevelControlState* state;
    float timer;

    Obj_GetPlayerObject(); /* result unused (retail does the same call) */
    state = (obj)->extra;
    timer = state->messageTimer;
    if (timer > 0.0f)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x42c);
        state->messageTimer = state->messageTimer - timeDelta;
        timer = state->messageTimer;
        if (timer < 0.0f)
        {
            state->messageTimer = 0.0f;
        }
    }
    if (state->latchesDisabled == 0)
    {
        mode6 = (*gMapEventInterface)->getMapAct((int)(obj)->anim.mapEventSlot);
        mode6 = __cntlzw(6 - (mode6 & 0xff));
        mode6 = mode6 >> 5;
        if ((((int)mode6 == 0) || (loadingDone = getCurSeqNoInt(), loadingDone == 0)) ||
            (mode6 = mainGetBit(GAMEBIT_WMRelated0A7F), mode6 == 0))
        {
            SCGameBitLatch_UpdateInverted(&state->latch, 0x10, -1, -1, 0xa7f, 0xa6);
            SCGameBitLatch_Update(&state->latch, 2, -1, -1, 0xa7f, 0xa8);
        }
        if (0x3c < state->frameCounter)
        {
            SCGameBitLatch_Update(&state->latch, 1, -1, -1, 0xada, 0xac);
        }
        SCGameBitLatch_Update(&state->latch, 0x20, -1, -1, 0xcbb, 0xc4);
    }
    fn_801F3F18(obj);
    state->frameCounter = state->frameCounter + 1;
    return;
}

void WM_LevelControl_init(GameObject* obj)
{
    WmLevelControlState* state;
    u8 mode;

    ObjGroup_AddObject((u32)obj, WMLEVELCONTROL_OBJGROUP);
    unlockLevel(mapGetDirIdx(0xb), 0, 0);
    state = obj->extra;
    state->unk0B = 0;
    state->unk06 = 0x1e;
    state->messageTimer = 300.0f;
    state->latch.activeMask = 0;
    lockLevel(0xf, 0);
    /* the 0xD1B..0xD1F chain marks how many Krazoa spirits the palace
       has received (wmspiritplace's progression); 0xF43/0xF44 pick the
       ambience variant. All cross-TU bits without established names. */
    mode = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        (*gMapEventInterface)->setMapAct(WMLEVELCONTROL_MAP_LIGHTFOOT, 1);
        (*gMapEventInterface)->setObjGroupStatus(WMLEVELCONTROL_MAP_LIGHTFOOT, 0, 1);
        break;
    case 2:
        mainSetBits(GAMEBIT_WMRelated0D1B, 1);
        mainSetBits(GAMEBIT_SH_ReturnedToWarpStone, 1);
        mainSetBits(GAMEBIT_WM_Warp3Enabled, 1);
        mainSetBits(GAMEBIT_WM_Warp4Enabled, 0);
        break;
    case 3:
        mainSetBits(GAMEBIT_WMRelated0D1B, 1);
        mainSetBits(GAMEBIT_WMRelated0D1C, 1);
        mainSetBits(GAMEBIT_WMRelated0A7F, 1);
        mainSetBits(GAMEBIT_WM_Warp3Enabled, 0);
        mainSetBits(GAMEBIT_WM_Warp4Enabled, 1);
        break;
    case 4:
        mainSetBits(GAMEBIT_WMRelated0D1B, 1);
        mainSetBits(GAMEBIT_WMRelated0D1C, 1);
        mainSetBits(GAMEBIT_WMRelated0D1D, 1);
        mainSetBits(GAMEBIT_WMRelated0A7F, 1);
        mainSetBits(GAMEBIT_WM_Warp3Enabled, 0);
        mainSetBits(GAMEBIT_WM_Warp4Enabled, 1);
        state->unk04 = -1;
        break;
    case 5:
        mainSetBits(GAMEBIT_WMRelated0D1B, 1);
        mainSetBits(GAMEBIT_WMRelated0D1C, 1);
        mainSetBits(GAMEBIT_WMRelated0D1D, 1);
        mainSetBits(GAMEBIT_WMRelated0D1E, 1);
        mainSetBits(GAMEBIT_WM_Warp3Enabled, 0);
        mainSetBits(GAMEBIT_WM_Warp4Enabled, 1);
        break;
    case 6:
        mainSetBits(GAMEBIT_WMRelated0D1B, 1);
        mainSetBits(GAMEBIT_WMRelated0D1C, 1);
        mainSetBits(GAMEBIT_WMRelated0D1D, 1);
        mainSetBits(GAMEBIT_WMRelated0D1E, 1);
        mainSetBits(GAMEBIT_WMRelated0D1F, 1);
        mainSetBits(GAMEBIT_WMRelated0164, 1);
        mainSetBits(GAMEBIT_WM_Warp3Enabled, 0);
        mainSetBits(GAMEBIT_WM_Warp4Enabled, 0);
        break;
    case 7:
        state->unk08 = 700;
        state->unk0A = 0x1e;
        state->unk06 = state->unk0A;
        state->latchesDisabled = 1;
        break;
    }
}

void WM_LevelControl_release(void)
{
}

void WM_LevelControl_initialise(void)
{
}
