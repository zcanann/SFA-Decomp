/*
 * WM_LevelCon (DLL 0x0209) - Krazoa Palace level control.
 *
 * WM_LevelControl_init seeds the palace's game-bit progression from the
 * map-event mode (the 0xD1B..0xD1F spirit chain consumed by WM_spiritplace and
 * friends); update shows the intro message while messageTimer runs,
 * drives the music game-bit latches, and calls the sky/light override
 * helper every frame. WM_LevelControl_updateSkyLighting cross-fades the
 * palace's sky, light, and fog colors toward their spirit-restored values
 * while the gWmLevelControlBlendFactor blend factor (held at 1.0 during
 * restore progress, decaying 0.02/tick after) is up.
 */
#include "dlls/objects/521_WM_LevelCon.h"

#include "game/objects/object.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/map_load.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/objseq_api.h"
#include "main/pi_dolphin_api.h"
#include "main/sky_api.h"
#include "sys/objects.h"

u8 gWmLevelControlSkyColorFrom[4] = {0x14, 0x20, 0x28, 0};
u8 gWmLevelControlSkyColorTo[4] = {0x12, 0x1E, 0x23, 0};
u8 gWmLevelControlLightColorFrom[4] = {0x7E, 0xAD, 0xB0, 0};
u8 gWmLevelControlLightColorTo[4] = {0xD2, 0xF1, 0xFF, 0};
u8 gWmLevelControlFogColorFrom[4] = {0x4E, 0x64, 0x6A, 0};
u8 gWmLevelControlFogColorTo[4] = {0x42, 0x56, 0x55, 0};

typedef struct {
    Vec3f vectors[4];
} WMLevelControlSkyVectorTable;

STATIC_ASSERT(sizeof(WMLevelControlSkyVectorTable) == 0x30);

#define WM_LEVEL_CONTROL_OBJ_GROUP 9

/* LightFoot Village map-event id (seeded from the palace spirit chain). */
#define WM_LEVEL_CONTROL_MAP_LIGHTFOOT 0xE

/* Sky light, color, and fog direction vectors. */
const WMLevelControlSkyVectorTable gWmLevelControlSkyVecTable = {
    {{-1.0f, -2.0f, -1.0f}, {1.0f, -2.0f, 1.0f}, {1.0f, -2.0f, 1.0f}, {1.0f, -0.25f, 1.0f}}};
u8 gWmLevelControlBlendedLightColor[4];  /* Blended light-color RGB output. */
u8 gWmLevelControlBlendedSkyColor[4];    /* Blended sky-color RGB output. */
u8 gWmLevelControlBlendedFogColor[4];    /* Blended fog-color RGB output. */
u8 gWmLevelControlBlendedLightIntensity; /* Blended light-intensity byte. */
f32 gWmLevelControlBlendFactor;          /* Current blend factor. */
f32 gWmLevelControlBlendHold;            /* Restore-blend hold value. */

ObjectDescriptor gWM_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_LevelControl_initialise,
    WM_LevelControl_release,
    0,
    (ObjectDescriptorCallback)WM_LevelControl_init,
    (ObjectDescriptorCallback)WM_LevelControl_update,
    WM_LevelControl_hitDetect,
    (ObjectDescriptorCallback)WM_LevelControl_render,
    (ObjectDescriptorCallback)WM_LevelControl_free,
    (ObjectDescriptorCallback)WM_LevelControl_getObjectTypeId,
    WM_LevelControl_getExtraSize,
};

static void WmLevelControl_holdBlendWhileRestoring(void) {
    if (lightningGetRemainingFraction() > 0.0f) {
        gWmLevelControlBlendHold = 1.0f;
        gWmLevelControlBlendFactor = 1.0f;
    }
}

const f32 gWmLevelControlBlendDecayPerTick[1] = {0.02f};
const f32 gWmLevelControlLightIntensityBase[1] = {32.0f};
const f32 gWmLevelControlLightIntensityRange[1] = {128.0f};
const f32 gWmLevelControlOverrideLightIntensity[1] = {100.0f};

static void WmLevelControl_blendColor(u8* output, const u8* from, const u8* to) {
    {
        int red = from[0];
        output[0] = (u8)(red + gWmLevelControlBlendFactor * (to[0] - red));
    }
    {
        int green = from[1];
        output[1] = (u8)(green + gWmLevelControlBlendFactor * (to[1] - green));
    }
    {
        int blue = from[2];
        output[2] = (u8)(blue + gWmLevelControlBlendFactor * (to[2] - blue));
    }
}

void WM_LevelControl_updateSkyLighting(GameObject* obj) {
    Vec3f auxiliaryDirection;
    Vec3f fromDirection;
    Vec3f toDirection;
    f32 newBlend;
    const Vec3f* directionTable;
    u8 skyColorActive;

    directionTable = gWmLevelControlSkyVecTable.vectors;
    auxiliaryDirection = directionTable[1];
    fromDirection = directionTable[2];
    toDirection = directionTable[3];

    if (mapEventGetMapAct(obj->anim.mapEventSlot) == 7) {
        return;
    }

    setDrawLights(0);
    skyColorActive = skyGetSlotFlag80(0);
    if (skyColorActive != 0) {
        skySetOverrideLightColorEnabled(0);
        skySetOverrideLightDirectionEnabled(0);
        skySetLightsEnabled(7, 0, 1);
        return;
    }

    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x88, 0xB7, 0xBA);
    if ((obj->userData1 & 4) == 0) {
        skySetLightsEnabled(1, 1, 0);
        obj->userData1 |= 4;
    } else {
        skySetLightsEnabled(1, 1, 1);
    }

    /*
     * Hold the blend at full while spirit-restore progress is running, then
     * decay it toward 0.
     */
    WmLevelControl_holdBlendWhileRestoring();
    newBlend = -(gWmLevelControlBlendDecayPerTick[0] * timeDelta - gWmLevelControlBlendFactor);
    gWmLevelControlBlendFactor = newBlend;
    if (newBlend < 0.0f) {
        gWmLevelControlBlendFactor = 0.0f;
    }

    /* Blend each color channel from source to target by the blend factor. */
    WmLevelControl_blendColor(gWmLevelControlBlendedLightColor, gWmLevelControlLightColorFrom,
                              gWmLevelControlLightColorTo);
    skySetBaseColor(1, gWmLevelControlBlendedLightColor[0], gWmLevelControlBlendedLightColor[1],
                    gWmLevelControlBlendedLightColor[2], 0x40, 0x40);

    WmLevelControl_blendColor(gWmLevelControlBlendedSkyColor, gWmLevelControlSkyColorFrom, gWmLevelControlSkyColorTo);
    skySetAmbientColor(1, gWmLevelControlBlendedSkyColor[0], gWmLevelControlBlendedSkyColor[1],
                     gWmLevelControlBlendedSkyColor[2]);

    WmLevelControl_blendColor(gWmLevelControlBlendedFogColor, gWmLevelControlFogColorFrom, gWmLevelControlFogColorTo);
    skySetMoonColor(1, gWmLevelControlBlendedFogColor[0], gWmLevelControlBlendedFogColor[1],
                       gWmLevelControlBlendedFogColor[2]);

    gWmLevelControlBlendedLightIntensity =
        gWmLevelControlBlendFactor * gWmLevelControlLightIntensityRange[0] + gWmLevelControlLightIntensityBase[0];
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(gWmLevelControlBlendFactor * (toDirection.x - fromDirection.x) + fromDirection.x,
                                 gWmLevelControlBlendFactor * (toDirection.y - fromDirection.y) + fromDirection.y,
                                 gWmLevelControlBlendFactor * (toDirection.z - fromDirection.z) + fromDirection.z,
                                 gWmLevelControlOverrideLightIntensity[0]);
    skySetLightDirection(1, auxiliaryDirection.x, auxiliaryDirection.y, auxiliaryDirection.z);
}

int WM_LevelControl_getExtraSize(void) {
    return sizeof(WMLevelControlState);
}

int WM_LevelControl_getObjectTypeId(void) {
    return 0;
}

void WM_LevelControl_free(GameObject* obj) {
    objFreeObjectType(obj, WM_LEVEL_CONTROL_OBJ_GROUP);
    Music_Trigger(MUSICTRIG_drako_3, 0);
    mainSetBits(GAMEBIT_WMRelated0A7F, 0);
    mainSetBits(GAMEBIT_KrazTest1Related0372, 1);
    mainSetBits(GAMEBIT_KrazTest1Related0390, 1);
}

void WM_LevelControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void WM_LevelControl_hitDetect(void) {
}

void WM_LevelControl_update(GameObject* obj) {
    u32 condition;
    int sequenceId;
    WMLevelControlState* state;
    f32 timer;

    Obj_GetPlayerObject(); /* Retail discards this result. */
    state = obj->extra;
    timer = state->messageTimer;
    if (timer > 0.0f) {
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        gameTextShow(0x42C);
        state->messageTimer -= timeDelta;
        timer = state->messageTimer;
        if (timer < 0.0f) {
            state->messageTimer = 0.0f;
        }
    }
    if (state->musicLatchesDisabled == 0) {
        condition = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
        condition = __cntlzw(6 - (condition & 0xFF));
        condition >>= 5;
        if ((((int)condition == 0) || (sequenceId = getCurSeqNo(), sequenceId == 0)) ||
            (condition = mainGetBit(GAMEBIT_WMRelated0A7F), condition == 0)) {
            GameBitLatch_UpdateInverted(&state->musicLatch, 0x10, -1, -1, 0xA7F, 0xA6);
            GameBitLatch_Update(&state->musicLatch, 2, -1, -1, 0xA7F, 0xA8);
        }
        if (state->frameCounter > 0x3C) {
            GameBitLatch_Update(&state->musicLatch, 1, -1, -1, 0xADA, 0xAC);
        }
        GameBitLatch_Update(&state->musicLatch, 0x20, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                            MUSICTRIG_PU3_Adventure_c4);
    }
    WM_LevelControl_updateSkyLighting(obj);
    state->frameCounter++;
}

void WM_LevelControl_init(GameObject* obj) {
    extern const f32 gWmLevelControlIntroMessageDuration;
    WMLevelControlState* state;
    u8 mode;

    objAddObjectType(obj, WM_LEVEL_CONTROL_OBJ_GROUP);
    unlockLevel(mapGetDirIdx(0xB), 0, 0);
    state = obj->extra;
    state->unknown0B = 0;
    state->unknown06 = 0x1E;
    state->messageTimer = gWmLevelControlIntroMessageDuration;
    state->musicLatch.activeMask = 0;
    lockLevel(0xF, 0);
    /* The 0xD1B..0xD1F chain tracks returned Krazoa spirits. */
    mode = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    switch (mode) {
    case 1:
        (*gMapEventInterface)->setMapAct(WM_LEVEL_CONTROL_MAP_LIGHTFOOT, 1);
        (*gMapEventInterface)->setObjGroupStatus(WM_LEVEL_CONTROL_MAP_LIGHTFOOT, 0, 1);
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
        state->unknown04 = -1;
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
        state->unknown08 = 700;
        state->unknown0A = 0x1E;
        state->unknown06 = state->unknown0A;
        state->musicLatchesDisabled = 1;
        break;
    }
}

const f32 gWmLevelControlIntroMessageDuration = 300.0f;

void WM_LevelControl_release(void) {
}

void WM_LevelControl_initialise(void) {
}
