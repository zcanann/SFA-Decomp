/*
 * WORLDplanet (DLL 0x1D2) - the Arwing destination-selection world map.
 */
#include "dlls/objects/466_WORLDplanet.h"

#include "dlls/objects/467.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/stream_api.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_004E_cameramodeworldmap.h"
#include "main/dll/hint_text_api.h"
#include "main/dll/partfx_interface.h"
#include "main/fcos16_approx_api.h"
#include "main/frame_timing.h"
#include "main/fsin16_approx_api.h"
#include "main/gamebits_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/loaded_file_flags.h"
#include "main/map_load.h"
#include "main/mapEvent.h"
#include "main/model.h"
#include "main/object_render.h"
#include "main/pad.h"
#include "main/pause_menu_api.h"
#include "main/rcp_dolphin.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"
#include "main/rcp_dolphin_api.h"

#define WORLDPLANET_MAIN_MAP_ID       0x2D
#define WORLDPLANET_MAP_PRELOAD_FLAG  0x10000000
#define WORLDPLANET_MAP_SELECTED_FLAG 0x20000000

#define WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN 0xA63
#define WORLDPLANET_HINT_UNLOCK_THRESHOLD  0xAD
#define WORLDPLANET_INPUT_STICK_THRESHOLD  0x23
#define WORLDPLANET_INPUT_REPEAT_FRAMES    0x32
#define WORLDPLANET_SAVE_FILE_SLOT         0
#define WORLDPLANET_CONFIRM_BUTTON         0x100
#define WORLDPLANET_CANCEL_BUTTON          0x200

#define WORLDPLANET_CAMERA_FOCUS_FRAMES 0x50

#define WORLDPLANET_STATE_FLAG_ENVFX_STARTED           0x01
#define WORLDPLANET_STATE_FLAG_CAMERA_SET              0x04
#define WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED 0x08

#define WORLDPLANET_FOX_OBJECT_ID            0x42FF5
#define WORLDPLANET_ARWING_OBJECT_ID         0x4300C
#define WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID  0x4300D
#define WORLDPLANET_FOX_SPAWN_OBJECT_ID      0x80F
#define WORLDPLANET_FOX_SPAWN_SETUP_SIZE     0x20
#define WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES 0x78
#define WORLDPLANET_FOX_SPAWN_MIN_FRAMES     0x708
#define WORLDPLANET_FOX_SPAWN_MAX_FRAMES     3000

#define WORLDPLANET_BOOT_MUSIC_TRIGGER       0x8F
#define WORLDPLANET_SELECT_TITLE_TEXT_ID     0x2A7
#define WORLDPLANET_SELECT_TITLE_FRAMES      0x19
#define WORLDPLANET_SELECTION_PFX_ID         0x6F2
#define WORLDPLANET_SELECTION_PFX_MODE       2
#define WORLDPLANET_SELECTION_PFX_TIMER      100
#define WORLDPLANET_ENVFX_OPEN_ID            0x21F
#define WORLDPLANET_COUNTDOWN_FRAMES         10
#define WORLDPLANET_CANCEL_LOCKOUT_FRAMES    0x1E
#define WORLDPLANET_TRANSITION_DELAY_FRAMES  5
#define WORLDPLANET_TRANSITION_ID            4
#define WORLDPLANET_ORBIT_SOUND_DELAY_FRAMES 2
#define WORLDPLANET_ORBIT_ROT_STEP           0x3C
#define WORLDPLANET_ORBIT_TILT_ANGLE         3000

#define WORLDPLANET_SKY_LIGHT_MASK  7
#define WORLDPLANET_SKY_COLOR_SCALE 0x40

typedef struct WorldPlanetFoxSpawnSetup {
    ObjPlacement base;
    u8 unknown18[0x08];
} WorldPlanetFoxSpawnSetup;

STATIC_ASSERT(sizeof(WorldPlanetFoxSpawnSetup) == WORLDPLANET_FOX_SPAWN_SETUP_SIZE);

#define WORLDPLANET_LERP_CHANNEL(dst, from, to, channel, t)                                                            \
    {                                                                                                                  \
        int value = (from).channel;                                                                                    \
        (dst).channel = value + (t) * (f32)((to).channel - value);                                                     \
    }

f32 gWorldPlanetPathProgress;
int gWorldPlanetLoadedMapId;
WorldPlanetColorRGBA8 gWorldPlanetCurSky;
WorldPlanetColorRGBA8 gWorldPlanetCurAmbient;
WorldPlanetColorRGBA8 gWorldPlanetCurMoon;
u8 gWorldPlanetCurIntensity;
f32 gWorldPlanetLightingLerpT;
int lbl_803DDD10;
s16 gWorldPlanetReselectDelayTimer;
s16 gWorldPlanetInputLockTimer;
u8 gWorldPlanetExitWarpTimer;
int gWorldPlanetSelectConfirmTimer;
f32 lbl_803DDD00;

void worldplanet_updateMapLighting(GameObject* obj) {
    f32 intensityScale;
    skySetLightsEnabled(WORLDPLANET_SKY_LIGHT_MASK, 1, 0);

    gWorldPlanetLightingLerpT = 0.0f;

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, red,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, green,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurSky, gWorldPlanetSkyColorFrom, gWorldPlanetSkyColorTo, blue,
                             gWorldPlanetLightingLerpT)
    skySetBaseColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurSky.red, gWorldPlanetCurSky.green,
                    gWorldPlanetCurSky.blue, WORLDPLANET_SKY_COLOR_SCALE, WORLDPLANET_SKY_COLOR_SCALE);

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, red,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, green,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurAmbient, gWorldPlanetAmbientFrom, gWorldPlanetAmbientTo, blue,
                             gWorldPlanetLightingLerpT)
    skySetAmbientColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurAmbient.red, gWorldPlanetCurAmbient.green,
                       gWorldPlanetCurAmbient.blue);

    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurMoon, gWorldPlanetMoonFrom, gWorldPlanetMoonTo, red,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurMoon, gWorldPlanetMoonFrom, gWorldPlanetMoonTo, green,
                             gWorldPlanetLightingLerpT)
    WORLDPLANET_LERP_CHANNEL(gWorldPlanetCurMoon, gWorldPlanetMoonFrom, gWorldPlanetMoonTo, blue,
                             gWorldPlanetLightingLerpT)
    skySetMoonColor(WORLDPLANET_SKY_LIGHT_MASK, gWorldPlanetCurMoon.red, gWorldPlanetCurMoon.green,
                    gWorldPlanetCurMoon.blue);

    intensityScale = 128.0f;
    gWorldPlanetCurIntensity = gWorldPlanetLightingLerpT * intensityScale + 32.0f;
    skySetLightDirection(WORLDPLANET_SKY_LIGHT_MASK, 0.739264f, 0.0f, 0.673415f);
}

u8 gWorldPlanetHintFlagTable[8] = {1, 1, 0, 1, 1, 0, 0, 0};
u8 gWorldPlanetDefaultSelectOrder[8] = {2, 4, 1, 0, 3, 0, 0, 0};
u8 gWorldPlanetSelectionToIndex[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetTitleStringIds[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetWarpMapIndices[6] = {0x76, 0x6E, 0x6F, 0x75, 0x74, 0};
u8 gWorldPlanetLoadMapIndices[6] = {0x3D, 0x3C, 0x3A, 0x3E, 0x3B, 0};
u8 gWorldPlanetBriefingSpeakerModel[8] = {2, 2, 1, 0, 0, 0, 0, 0};
int gWorldPlanetSavedSelection = -1;
WorldPlanetColorRGBA8 gWorldPlanetAmbientFrom = {0x21, 0x35, 0x3F, 0};
WorldPlanetColorRGBA8 gWorldPlanetAmbientTo = {9, 0x0F, 0x1E, 0};
WorldPlanetColorRGBA8 gWorldPlanetSkyColorFrom = {0xFF, 0xE1, 0x87, 0};
WorldPlanetColorRGBA8 gWorldPlanetSkyColorTo = {0xC8, 0xE7, 0xFF, 0};
WorldPlanetColorRGBA8 gWorldPlanetMoonFrom = {0x74, 0xA2, 0x85, 0};
WorldPlanetPaddedColorRGBA8 gWorldPlanetMoonTo = {0x13, 0x23, 0x36, 0, {0, 0, 0, 0}};

/* Per-WorldPlanetSlot parameter arrays. Entries are WorldPlanetSlot 0..4
 * (Walled City / CloudRunner / Dinosaur / Dragon Rock / DarkIce).
 *   sWorldPlanetOrbitObjectIds: the orbiting island objects. Each frame they are placed on the orbit
 *          ring (localPos from orbit radius + the angle offset) and spun; they are
 *          also the camera's focus/action target on select & confirm and carry
 *          the binary selection highlight (WorldObjState.effectState 0/1). Slot
 *          2's entry is WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID (special-cased in the
 *          orbit placement).
 *   sWorldPlanetOrbitAngleOffsets: 0/0x4000/0x5FA0/0x8000/0xC000
 *          (0/90/~135/180/270 deg) spacing the islands evenly around the ring.
 *   sWorldPlanetFlightPathObjectIds: per-slot objects that rotate with the map and each hold the flight
 *          PATH for one destination. When a planet is selected the small ferry
 *          Arwing (WORLDPLANET_ARWING_OBJECT_ID) is interpolated along the
 *          selected slot's path each frame; effectState
 *          = locked(0) / available(1) / selected(2). Verified live that all five
 *          routes exist - the Arwing is just unlock-gated (the effectState-0 branch
 *          hides it), so in normal play only the reachable planet's is ever seen. */
static int sWorldPlanetOrbitObjectIds[WORLDPLANET_PLANET_COUNT] = {0x00042FEA, 0x00042FE8, 0x0004300D, 0x00042FE9,
                                                                   0x00042FEB};
static int sWorldPlanetOrbitAngleOffsets[WORLDPLANET_PLANET_COUNT] = {0, 0x4000, 0x5FA0, 0x8000, 0xC000};
static int sWorldPlanetFlightPathObjectIds[WORLDPLANET_PLANET_COUNT] = {0x00043099, 0x00042FFF, 0x0004309A, 0x00043098,
                                                                        0x00043097};

/* unlock gamebit per WorldPlanetSlot: [0] Walled City, [1] CloudRunner,
 * [2] Dinosaur Planet (== WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, always set),
 * [3] Dragon Rock, [4] DarkIce Mines. */
int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT] = {1019, 1018, 2659, 1020, 1017};

int worldplanet_getExtraSize(void) {
    return sizeof(WorldPlanetState);
}

int worldplanet_getObjectTypeId(void) {
    return 0;
}

void worldplanet_free(void) {
    setShowWorldMapHud(0);
    return;
}

void worldplanet_render(GameObject* obj, u32 renderArg2, u32 renderArg3, u32 renderArg4, u32 renderArg5, s8 visible) {
    int isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
    return;
}

void worldplanet_hitDetect(void) {
    return;
}

static inline void worldplanet_spawnFox(GameObject* obj, WorldPlanetState* state) {
    ObjPlacement* def;
    state->foxSpawnTimer = randomGetRange(WORLDPLANET_FOX_SPAWN_MIN_FRAMES, WORLDPLANET_FOX_SPAWN_MAX_FRAMES);
    def = (ObjPlacement*)(obj)->anim.placementData;
    if ((u8)Obj_CanSetupObject() != 0) {
        WorldPlanetFoxSpawnSetup* setup = (WorldPlanetFoxSpawnSetup*)Obj_AllocObjectSetup(
            WORLDPLANET_FOX_SPAWN_SETUP_SIZE, WORLDPLANET_FOX_SPAWN_OBJECT_ID);
        setup->base.color[0] = def->color[0];
        setup->base.color[2] = def->color[2];
        setup->base.color[1] = def->color[1];
        setup->base.color[3] = def->color[3];
        setup->base.posX = (obj)->anim.localPosX;
        setup->base.posY = (obj)->anim.localPosY;
        setup->base.posZ = (obj)->anim.localPosZ;
        objSetupObject((ObjPlacement*)setup, 5, (obj)->anim.mapEventSlot, -1, NULL);
    }
}

void worldplanet_update(GameObject* obj) {
    GameObject* orbitObject;
    u8 planetIndex;
    u8 prevPlanet;
    GameObject* mapObject;
    int buttons;
    WorldPlanetState* state;
    u8 done;
    u8 i;
    int objId;
    WorldObjEffectParams effectParams;
    s8 inputX;
    s8 inputY;

    state = (obj)->extra;
    done = 0;
    state->foxSpawnTimer -= 1;
    if (state->foxSpawnTimer == 1) {
        worldplanet_spawnFox(obj, state);
    }
    if (state->foxSpawnTimer < 0) {
        state->foxSpawnTimer = 0;
    }
    worldplanet_updateMapLighting(obj);
    if (gWorldPlanetInputLockTimer != 0) {
        gWorldPlanetInputLockTimer -= 1;
    }
    if (gWorldPlanetExitWarpTimer != 0) {
        gWorldPlanetExitWarpTimer -= 1;
        if (gWorldPlanetExitWarpTimer == 0) {
            setIsOvercast(1);
            setDrawCloudsAndLights(1);
            setDrawLights(1);
            warpToMap(gWorldPlanetWarpMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]], 0);
        }
    } else {
        setFrameCountdown(1);
        if ((state->flags & WORLDPLANET_STATE_FLAG_CAMERA_SET) == 0) {
            (*gCameraInterface)->setMode(CAMERA_MODE_WORLD_MAP_RESOURCE_ID, 1, 0, 0, NULL, 0, 0xff);
            (*gCameraInterface)->setFocus((void*)obj, 0);
            state->flags |= WORLDPLANET_STATE_FLAG_CAMERA_SET;
        } else if ((state->flags & WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED) == 0) {
            objId = sWorldPlanetOrbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]];
            (*gCameraInterface)->releaseAction(&objId, CAMERA_MODE_WORLD_MAP_ACTION_SET_FOCUS_IMMEDIATE);
            state->flags |= WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED;
            {
                GameObject* briefingPortrait = ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                ((WorldObjState*)briefingPortrait->extra)->controlByte =
                    gWorldPlanetBriefingSpeakerModel[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & WORLDPLANET_STATE_FLAG_ENVFX_STARTED) == 0) {
            state->flags |= WORLDPLANET_STATE_FLAG_ENVFX_STARTED;
            getEnvfxAct(0, 0, WORLDPLANET_ENVFX_OPEN_ID, 0);
            setIsOvercast(0);
            setDrawLights(0);
        }
        buttons = getButtonsJustPressed(0);
        effectParams.dispatchTimer = WORLDPLANET_SELECTION_PFX_TIMER;
        effectParams.offsetX = 59.3736f;
        effectParams.offsetY = 39.745197f;
        effectParams.offsetZ = -42.603f;
        (*gPartfxInterface)
            ->spawnObject((void*)obj, WORLDPLANET_SELECTION_PFX_ID, &effectParams, WORLDPLANET_SELECTION_PFX_MODE, -1,
                          NULL);
        worldplanet_readMapInput(obj, &inputX, &inputY);
        (obj)->anim.rotZ -= 10;
        (obj)->anim.rotY = 0x3448;
        (obj)->anim.rotX = 0x4000;
        {
            GameObject* fox = ObjList_FindObjectById(WORLDPLANET_FOX_OBJECT_ID);
            fox->anim.rotZ = (obj)->anim.rotZ;
            fox->anim.rotY = (obj)->anim.rotY;
            fox->anim.rotX = (obj)->anim.rotX;
        }
        mapObject = ObjList_FindObjectById(WORLDPLANET_ARWING_OBJECT_ID);
        ((WorldObjState*)mapObject->extra)->effectState = state->selectionLocked;
        prevPlanet = state->selectedPlanet;
        {
            int z[3];
            int* ids;
            u8* hints;
            z[0] = 0;
            z[1] = z[0];
            z[2] = z[1];
            ids = gWorldPlanetGameBitTable;
            hints = gWorldPlanetHintFlagTable;
            for (; z[2] < WORLDPLANET_PLANET_COUNT; z[2]++) {
                if (mainGetBit(*ids) != 0) {
                    z[0] = 1;
                    if (*hints != 0 && (s32)getNextTaskHintText() > WORLDPLANET_HINT_UNLOCK_THRESHOLD) {
                        z[0] = 0;
                    }
                    if ((u8)z[0]) {
                        z[1] |= 1 << z[2];
                    }
                }
                ids += 1;
                hints += 1;
            }
            state->unlockedPlanetMask = z[1];
        }
        if (gWorldPlanetSelectConfirmTimer == 0 && state->selectionLocked == 0) {
            while (!done) {
                state->selectedPlanet = state->selectedPlanet + inputX;
                if (state->selectedPlanet < 0) {
                    state->selectedPlanet = 4;
                } else if (state->selectedPlanet >= WORLDPLANET_PLANET_COUNT) {
                    state->selectedPlanet = 0;
                }
                done = 1;
            }
            pauseMenuSetupTitle(WORLDPLANET_SELECT_TITLE_TEXT_ID, gWorldPlanetTitleStringIds[state->selectedPlanet],
                                WORLDPLANET_SELECT_TITLE_FRAMES, 0);
            /* obj->userData1 is the GameObject's generic per-instance state word
             * (its meaning is per-DLL); worldplanet uses it as a one-shot latch:
             * 0 until the first selection has been set up, 1 thereafter. This
             * block runs on a real selection change OR that first frame, but the
             * camera swoosh (releaseAction) + select SFX below are gated on the
             * latch so they fire only on genuine changes, not on the initial open. */
            if (prevPlanet != state->selectedPlanet || (obj)->userData1 == 0) {
                if ((obj)->userData1 != 0) {
                    objId = sWorldPlanetOrbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, CAMERA_MODE_WORLD_MAP_ACTION_SET_FOCUS);
                    Sfx_PlayFromObject(0, SFXTRIG_crf_babyambi3);
                }
                gWorldPlanetPathProgress = 0.0f;
                {
                    WorldObjState* planetState =
                        ObjList_FindObjectById(sWorldPlanetOrbitObjectIds[gWorldPlanetSelectionToIndex[prevPlanet]])
                            ->extra;
                    GameObject* planetObj;
                    planetState->effectState = 0;
                    planetObj = ObjList_FindObjectById(
                        sWorldPlanetOrbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                    ((WorldObjState*)planetObj->extra)->effectState = 1;
                }
                (obj)->userData1 = 1;
            }
        }
        gWorldPlanetPathProgress += 0.2f;
        if (gWorldPlanetPathProgress >= 21.0f) {
            gWorldPlanetPathProgress = 0.0f;
        }
        for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++) {
            GameObject* planet;
            WorldObjState* pstate;
            planet = ObjList_FindObjectById(sWorldPlanetFlightPathObjectIds[i]);
            pstate = planet->extra;
            planet->anim.rotY = (obj)->anim.rotY;
            planet->anim.rotX = (obj)->anim.rotX;
            if (state->selectionLocked != 0 || (((int)(u32)state->unlockedPlanetMask >> i) & 1) == 0) {
                pstate->effectState = 0;
                if ((int)i == state->selectedPlanet) {
                    mapObject->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            } else if ((int)i == state->selectedPlanet) {
                u32 fi;
                u32 ni;
                WorldObjPathSegmentWork* segment;
                f32 x0;
                f32 x1;
                f32 y0;
                f32 y1;
                f32 z0;
                f32 z1;
                f32 frac;
                s16 yaw;
                s16 dyaw;
                fi = (int)gWorldPlanetPathProgress & 0xff;
                ni = (fi + 2) & 0xff;
                frac = gWorldPlanetPathProgress - fi;
                segment = WorldObj_GetPathSegmentWork(pstate, fi);
                x0 = segment->start.x;
                x1 = segment->end.x;
                y0 = segment->start.y;
                y1 = segment->end.y;
                z0 = segment->start.z;
                z1 = segment->end.z;
                pstate->effectState = 2;
                yaw = getAngle(x1 - x0, z1 - z0);
                dyaw = ((ni >= 0x16) ? yaw
                                     : (s16)getAngle(WorldObj_GetPathSegmentWork(pstate, ni)->start.x - x1,
                                                     WorldObj_GetPathSegmentWork(pstate, ni)->start.z - z1)) -
                       (u16)yaw;
                if (dyaw > 0x8000) {
                    dyaw = (s16)(dyaw - 0xffff);
                }
                if (dyaw < -0x8000) {
                    dyaw = (s16)(dyaw + 0xffff);
                }
                if (getWorldMapVoiceoverTimer() != 0) {
                    mapObject->anim.flags |= OBJANIM_FLAG_HIDDEN;
                } else {
                    mapObject->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                }
                mapObject->anim.rotX = (frac * dyaw + yaw);
                mapObject->anim.localPosX = frac * (x1 - x0) + x0;
                mapObject->anim.localPosY = frac * (y1 - y0) + y0;
                mapObject->anim.localPosZ = frac * (z1 - z0) + z0;
            } else {
                pstate->effectState = 1;
            }
        }
        mapObject =
            ObjList_FindObjectById(sWorldPlanetOrbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
        if (getLoadedFileFlags(WORLDPLANET_SAVE_FILE_SLOT) == 0 && gWorldPlanetInputLockTimer == 0) {
            switch (state->selectionLocked) {
            case 0:
                if (gWorldPlanetReselectDelayTimer != 0) {
                    gWorldPlanetReselectDelayTimer -= 1;
                } else if (gWorldPlanetSelectConfirmTimer == 0 &&
                           (state->unlockedPlanetMask & (1 << state->selectedPlanet)) != 0 &&
                           (buttons & WORLDPLANET_CONFIRM_BUTTON) != 0) {
                    gWorldPlanetSelectConfirmTimer = WORLDPLANET_COUNTDOWN_FRAMES;
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                }
                if (gWorldPlanetSelectConfirmTimer != 0) {
                    Pause_ResetMenuFrameCounter();
                    gWorldPlanetSelectConfirmTimer -= 1;
                    if (gWorldPlanetSelectConfirmTimer <= 1) {
                        gWorldPlanetSelectConfirmTimer = 0;
                        Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                        (*gCameraInterface)->setFocus(mapObject, WORLDPLANET_CAMERA_FOCUS_FRAMES);
                        state->selectionLocked = 1;
                        (*gCameraInterface)
                            ->releaseAction(&state->selectionLocked, CAMERA_MODE_WORLD_MAP_ACTION_SET_MODE);
                        {
                            GameObject* briefingPortrait =
                                ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                            ((WorldObjState*)briefingPortrait->extra)->controlByte =
                                gWorldPlanetBriefingSpeakerModel[state->selectedPlanet];
                        }
                        gWorldPlanetLoadedMapId = loadMapAndParent(
                            gWorldPlanetLoadMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                        lockLevel(gWorldPlanetLoadedMapId, 1);
                        loadModelAndAnimTabs();
                        lbl_803DDD00 = 0.0f;
                        gWorldPlanetSavedSelection = state->selectedPlanet;
                    }
                }
                break;
            case 1:
                Pause_ResetMenuFrameCounter();
                if (!lbl_803DDD00) {
                    lbl_803DDD00 = 1.0f;
                }
                if ((buttons & WORLDPLANET_CANCEL_BUTTON) != 0) {
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_greatfox_lp);
                    Music_StopChannelsByPriorityGroup(2, MUSIC_CHANNEL_STOP_FADE, 1000);
                    (*gCameraInterface)->setFocus((void*)obj, WORLDPLANET_CAMERA_FOCUS_FRAMES);
                    state->selectionLocked = 0;
                    gWorldPlanetReselectDelayTimer = WORLDPLANET_CANCEL_LOCKOUT_FRAMES;
                    (*gCameraInterface)->releaseAction(&state->selectionLocked, CAMERA_MODE_WORLD_MAP_ACTION_SET_MODE);
                    unlockLevel(gWorldPlanetLoadedMapId, 1, 0);
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                    gWorldPlanetInputLockTimer = WORLDPLANET_COUNTDOWN_FRAMES;
                } else if ((buttons & WORLDPLANET_CONFIRM_BUTTON) != 0) {
                    (*gScreenTransitionInterface)->start(WORLDPLANET_TRANSITION_ID, SCREEN_TRANSITION_BLACK);
                    Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_DEFAULT, 0);
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                    setShowWorldMapHud(0);
                    gWorldPlanetExitWarpTimer = WORLDPLANET_TRANSITION_DELAY_FRAMES;
                    lbl_803DDD10 = 0;
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_PRELOAD_FLAG);
                }
                break;
            }
        } else {
            Pause_ResetMenuFrameCounter();
        }
        {
            u16 orbitAngle;
            f32 orbitRadius;
            {
                u8 spin = 0;
                orbitAngle = -(obj)->anim.rotZ;
                for (; spin < WORLDPLANET_PLANET_COUNT; spin++) {
                    GameObject* planetObj;
                    planetObj = ObjList_FindObjectById(sWorldPlanetFlightPathObjectIds[spin]);
                    planetObj->anim.rotZ = -orbitAngle;
                }
            }
            for (planetIndex = 0, orbitRadius = 220.0f; planetIndex < WORLDPLANET_PLANET_COUNT; planetIndex++) {
                int* angleOffsetEntry;
                int tableOffsetBytes = planetIndex * sizeof(sWorldPlanetOrbitObjectIds[0]);
                orbitObject = ObjList_FindObjectById(*(int*)((u8*)sWorldPlanetOrbitObjectIds + tableOffsetBytes));
                if (*(int*)((u8*)sWorldPlanetOrbitObjectIds + tableOffsetBytes) ==
                    WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID) {
                    orbitObject->anim.rotX =
                        orbitAngle + *(int*)((u8*)sWorldPlanetOrbitAngleOffsets + tableOffsetBytes) + 0x4000;
                } else {
                    orbitObject->anim.rotX += WORLDPLANET_ORBIT_ROT_STEP;
                }
                if (state->orbitSoundFrameCount > WORLDPLANET_ORBIT_SOUND_DELAY_FRAMES) {
                    Sfx_KeepAliveLoopedObjectSound(orbitObject, SFXTRIG_crf_babyambi2);
                }
                orbitObject->anim.localPosX =
                    orbitRadius *
                        fsin16Approx(orbitAngle + *(angleOffsetEntry = (int*)((u8*)sWorldPlanetOrbitAngleOffsets +
                                                                              tableOffsetBytes))) *
                        fcos16Approx(WORLDPLANET_ORBIT_TILT_ANGLE) +
                    (obj)->anim.localPosX;
                orbitObject->anim.localPosY = orbitRadius * fsin16Approx(orbitAngle + *angleOffsetEntry) *
                                                  fsin16Approx(WORLDPLANET_ORBIT_TILT_ANGLE) +
                                              (obj)->anim.localPosY;
                orbitObject->anim.localPosZ =
                    orbitRadius * fcos16Approx(orbitAngle + *angleOffsetEntry) + (obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}

void worldplanet_readMapInput(GameObject* obj, s8* outX, s8* outY) {
    WorldPlanetState* state = obj->extra;
    s8 stickX;
    s8 stickY;
    s8 resX;
    s8 resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(WORLDPLANET_SAVE_FILE_SLOT) == 0) {
        if (stickX < -WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->previousStickX >= -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resX = -1;
            state->stickXRepeatTimer = 0;
        }
        if (stickX > WORLDPLANET_INPUT_STICK_THRESHOLD && state->previousStickX <= WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resX = 1;
            state->stickXRepeatTimer = 0;
        }
        if (stickY < -WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->previousStickY >= -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resY = -1;
            state->stickYRepeatTimer = 0;
        }
        if (stickY > WORLDPLANET_INPUT_STICK_THRESHOLD && state->previousStickY <= WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resY = 1;
            state->stickYRepeatTimer = 0;
        }
        state->previousStickY = stickY;
        if (state->previousStickY < -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickYRepeatTimer++;
        } else if (state->previousStickY > WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickYRepeatTimer++;
        } else {
            state->stickYRepeatTimer = 0;
        }
        if (state->stickYRepeatTimer > WORLDPLANET_INPUT_REPEAT_FRAMES) {
            state->previousStickY = 0;
            state->stickYRepeatTimer = 0;
        }
        state->previousStickX = stickX;
        if (state->previousStickX < -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickXRepeatTimer++;
        } else if (state->previousStickX > WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickXRepeatTimer++;
        } else {
            state->stickXRepeatTimer = 0;
        }
        if (state->stickXRepeatTimer > WORLDPLANET_INPUT_REPEAT_FRAMES) {
            state->previousStickX = 0;
            state->stickXRepeatTimer = 0;
        }
        *outX = resX;
        *outY = resY;
    } else {
        *outX = 0;
        *outY = 0;
    }
}

void worldplanet_init(GameObject* obj) {
    WorldPlanetState* state;
    int z[3];
    int layer;
    int j;

    state = obj->extra;
    gWorldPlanetSelectConfirmTimer = 0;
    mainSetBits(WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, 1);
    z[0] = 0;
    z[1] = z[0];
    z[2] = z[1];
    for (; z[2] < WORLDPLANET_PLANET_COUNT; z[2]++) {
        if (mainGetBit(gWorldPlanetGameBitTable[z[2]]) != 0) {
            z[0] = 1;
            if (gWorldPlanetHintFlagTable[z[2]] != 0) {
                if ((s32)getNextTaskHintText() > WORLDPLANET_HINT_UNLOCK_THRESHOLD) {
                    z[0] = 0;
                }
            }
            if ((u8)z[0] != 0) {
                z[1] |= 1 << z[2];
            }
        }
    }
    state->unlockedPlanetMask = z[1];
    if (gWorldPlanetSavedSelection != -1) {
        state->selectedPlanet = gWorldPlanetSavedSelection;
    } else {
        for (j = 0; j < WORLDPLANET_PLANET_COUNT; j++) {
            if (mainGetBit(gWorldPlanetGameBitTable[gWorldPlanetDefaultSelectOrder[j]]) != 0) {
                state->selectedPlanet = gWorldPlanetDefaultSelectOrder[j];
                break;
            }
        }
    }
    gWorldPlanetExitWarpTimer = 0;
    setDrawLights(0);
    audioStopByMask(0xf);
    Music_Trigger(WORLDPLANET_BOOT_MUSIC_TRIGGER, 1);
    gWorldPlanetPathProgress = 0.0f;
    setShowWorldMapHud(1);
    gWorldPlanetLoadedMapId = -1;
    unlockLevel(0, 0, 1);
    mapUnload(WORLDPLANET_MAIN_MAP_ID, WORLDPLANET_MAP_PRELOAD_FLAG);
    layer = getCurMapLayer();
    (*gMapEventInterface)->savePoint(&obj->anim.localPosX, 0, 0, layer);
    (*gScreenTransitionInterface)->step(WORLDPLANET_CANCEL_LOCKOUT_FRAMES, SCREEN_TRANSITION_BLACK);
    gWorldPlanetInputLockTimer = WORLDPLANET_COUNTDOWN_FRAMES;
    mainSetBits(gWorldPlanetGameBitTable[WORLDPLANET_SLOT_DINOSAUR_PLANET], 1);
    state->foxSpawnTimer = WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES;
    skySetEnvFxFlags(0);
}

void worldplanet_release(void) {
}

void worldplanet_initialise(void) {
}

ObjectDescriptor gWorldPlanetObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)worldplanet_initialise,
    (ObjectDescriptorCallback)worldplanet_release,
    0,
    (ObjectDescriptorCallback)worldplanet_init,
    (ObjectDescriptorCallback)worldplanet_update,
    (ObjectDescriptorCallback)worldplanet_hitDetect,
    (ObjectDescriptorCallback)worldplanet_render,
    (ObjectDescriptorCallback)worldplanet_free,
    (ObjectDescriptorCallback)worldplanet_getObjectTypeId,
    worldplanet_getExtraSize,
};
