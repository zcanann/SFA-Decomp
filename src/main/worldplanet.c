#include "main/dll/partfx_interface.h"
#include "main/audio/sfx.h"
#include "main/audio/music_api.h"
#include "main/render_envfx_api.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/object_api.h"

#include "main/object.h"
#include "main/mapEvent.h"
#include "main/screen_transition.h"
#include "main/worldobj.h"
#include "main/worldplanet.h"
#include "main/pad.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/stream_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/model.h"
#include "main/loaded_file_flags.h"
#include "main/map_load.h"
#include "main/rcp_dolphin.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/hint_text_api.h"
#include "main/pause_menu_api.h"

u8 gWorldPlanetHintFlagTable[8] = {1, 1, 0, 1, 1, 0, 0, 0};
u8 gWorldPlanetDefaultSelectOrder[8] = {2, 4, 1, 0, 3, 0, 0, 0};
u8 gWorldPlanetSelectionToIndex[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetTitleStringIds[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetWarpMapIndices[6] = {0x76, 0x6E, 0x6F, 0x75, 0x74, 0};
u8 gWorldPlanetLoadMapIndices[6] = {0x3D, 0x3C, 0x3A, 0x3E, 0x3B, 0};
u8 gWorldPlanetBriefingSpeakerModel[8] = {2, 2, 1, 0, 0, 0, 0, 0};
int gWorldPlanetSavedSelection = -1;
u8 gWorldPlanetLightFrom[4] = {0x21, 0x35, 0x3F, 0};
u8 gWorldPlanetLightTo[4] = {9, 0x0F, 0x1E, 0};
u8 gWorldPlanetSkyColorFrom[4] = {0xFF, 0xE1, 0x87, 0};
u8 gWorldPlanetSkyColorTo[4] = {0xC8, 0xE7, 0xFF, 0};
u8 gWorldPlanetAmbientFrom[4] = {0x74, 0xA2, 0x85, 0};
u8 gWorldPlanetAmbientTo[8] = {0x13, 0x23, 0x36, 0, 0, 0, 0, 0};

#define WORLDPLANET_CAMMODE_WORLDMAP 0x4e /* cameramode DLL dll_004E_cameramodeworldmap */

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
/* unlock gamebit per WorldPlanetSlot: [0] Walled City, [1] CloudRunner,
 * [2] Dinosaur Planet (== WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, always set),
 * [3] Dragon Rock, [4] DarkIce Mines. */
int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT] = {1019, 1018, 2659, 1020, 1017};
extern int gWorldPlanetSelectConfirmTimer;
extern u8 gWorldPlanetExitWarpTimer;
extern s16 gWorldPlanetInputLockTimer;
extern int gWorldPlanetLoadedMapId;
extern f32 gWorldPlanetPathProgress;

extern f32 lbl_803DDD00;
extern s16 gWorldPlanetReselectDelayTimer;
extern int lbl_803DDD10;
extern int gWorldPlanetObjectIdTable[3][5]; /* [row][WorldPlanetSlot]; see definition for row meanings */
/* per-planet mission-briefing speaker model (WorldMapBriefingSpeaker), indexed by WorldPlanetSlot */

#include "main/fsin16_approx_api.h"
#include "main/fcos16_approx_api.h"
#include "main/worldplanet_lighting.h"
extern f32 gWorldPlanetPfxOffsetX;
extern f32 gWorldPlanetPfxOffsetY;
extern f32 gWorldPlanetPfxOffsetZ;
extern f32 gWorldPlanetPathProgressStep;
extern f32 gWorldPlanetPathProgressMax;
extern f32 gWorldPlanetOrbitRadius;

int worldplanet_getExtraSize(void)
{
    return sizeof(WorldPlanetState);
}

int worldplanet_getObjectTypeId(void)
{
    return 0;
}

void worldplanet_free(void)
{
    setShowWorldMapHud(0);
    return;
}

void worldplanet_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int draw;

    draw = visible;
    if (draw != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
    return;
}

void worldplanet_hitDetect(void)
{
    return;
}

void worldplanet_readMapInput(GameObject* obj, u8* outX, u8* outY);

void worldplanet_update(GameObject* obj)
{
    u8 prevPlanet;
    GameObject* arwing;
    int buttons;
    int(*tbl)[5];
    WorldPlanetState* state;
    u8 done;
    u8 i;
    u8 b;
    int objId;
    WorldObjEffectParams pfx;
    struct
    {
        u8 inY;
        u8 inX[3];
    } in;

    tbl = gWorldPlanetObjectIdTable;
    state = (obj)->extra;
    done = 0;
    state->foxSpawnTimer -= 1;
    if (state->foxSpawnTimer == 1)
    {
        int def;
        state->foxSpawnTimer = randomGetRange(WORLDPLANET_FOX_SPAWN_MIN_FRAMES, 3000);
        def = *(int*)&(obj)->anim.placementData;
        if (Obj_IsLoadingLocked() != 0)
        {
            WorldObjSetup* setup = (WorldObjSetup*)Obj_AllocObjectSetup(0x20, WORLDPLANET_FOX_SPAWN_OBJECT_ID);
            ((ObjPlacement*)setup)->color[0] = ((ObjPlacement*)def)->color[0];
            ((ObjPlacement*)setup)->color[2] = ((ObjPlacement*)def)->color[2];
            ((ObjPlacement*)setup)->color[1] = ((ObjPlacement*)def)->color[1];
            ((ObjPlacement*)setup)->color[3] = ((ObjPlacement*)def)->color[3];
            ((ObjPlacement*)setup)->posX = (obj)->anim.localPosX;
            ((ObjPlacement*)setup)->posY = (obj)->anim.localPosY;
            ((ObjPlacement*)setup)->posZ = (obj)->anim.localPosZ;
            Obj_SetupObject((ObjPlacement*)setup, 5, (obj)->anim.mapEventSlot, -1, NULL);
        }
    }
    if (state->foxSpawnTimer < 0)
    {
        state->foxSpawnTimer = 0;
    }
    worldplanet_updateMapLighting((int)obj);
    if (gWorldPlanetInputLockTimer != 0)
    {
        gWorldPlanetInputLockTimer -= 1;
    }
    if (gWorldPlanetExitWarpTimer != 0)
    {
        gWorldPlanetExitWarpTimer -= 1;
        if (gWorldPlanetExitWarpTimer == 0)
        {
            setIsOvercast(1);
            setDrawCloudsAndLights(1);
            setDrawLights(1);
            warpToMap(gWorldPlanetWarpMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]], 0);
        }
    }
    else
    {
        setFrameCountdown_800202c4(1);
        if ((state->flags & WORLDPLANET_STATE_FLAG_CAMERA_SET) == 0)
        {
            (*gCameraInterface)->setMode(WORLDPLANET_CAMMODE_WORLDMAP, 1, 0, 0, NULL, 0, 0xff);
            (*gCameraInterface)->setFocus((void*)obj, 0);
            state->flags |= WORLDPLANET_STATE_FLAG_CAMERA_SET;
        }
        else if ((state->flags & WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED) == 0)
        {
            objId = tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]];
            (*gCameraInterface)->releaseAction(&objId, 2);
            state->flags |= WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED;
            {
                GameObject* briefingPortrait = ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                ((WorldObjState*)briefingPortrait->extra)->controlByte =
                    gWorldPlanetBriefingSpeakerModel[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & WORLDPLANET_STATE_FLAG_ENVFX_STARTED) == 0)
        {
            state->flags |= WORLDPLANET_STATE_FLAG_ENVFX_STARTED;
            getEnvfxAct(0, 0, WORLDPLANET_ENVFX_OPEN_ID, 0);
            setIsOvercast(0);
            setDrawLights(0);
        }
        buttons = getButtonsJustPressed(0);
        pfx.dispatchTimer = 100;
        pfx.offsetX = gWorldPlanetPfxOffsetX;
        pfx.offsetY = gWorldPlanetPfxOffsetY;
        pfx.offsetZ = gWorldPlanetPfxOffsetZ;
        (*gPartfxInterface)->spawnObject((void*)obj, WORLDPLANET_SELECTION_PFX_ID, &pfx, 2, -1, NULL);
        worldplanet_readMapInput(obj, (u8*)in.inX, &in.inY);
        (obj)->anim.rotZ -= 10;
        (obj)->anim.rotY = 0x3448;
        (obj)->anim.rotX = 0x4000;
        {
            GameObject* fox = ObjList_FindObjectById(WORLDPLANET_FOX_OBJECT_ID);
            fox->anim.rotZ = (obj)->anim.rotZ;
            fox->anim.rotY = (obj)->anim.rotY;
            fox->anim.rotX = (obj)->anim.rotX;
        }
        arwing = ObjList_FindObjectById(WORLDPLANET_ARWING_OBJECT_ID);
        ((WorldObjState*)arwing->extra)->effectState = state->selectionLocked;
        prevPlanet = state->selectedPlanet;
        {
            int z[3];
            int* ids;
            u8* hints;
            z[0] = 0;
            z[1] = z[0];
            z[2] = z[1];
            ids = tbl[3];
            hints = gWorldPlanetHintFlagTable;
            for (; z[2] < 5; z[2]++)
            {
                if (mainGetBit(*ids) != 0)
                {
                    z[0] = 1;
                    if (*hints != 0 && (s32)getNextTaskHintText() > 0xad)
                    {
                        z[0] = 0;
                    }
                    if ((u8)z[0])
                    {
                        z[1] |= 1 << z[2];
                    }
                }
                ids += 1;
                hints += 1;
            }
            state->unlockedPlanetMask = z[1];
        }
        if (gWorldPlanetSelectConfirmTimer == 0 && (u8)state->selectionLocked == 0)
        {
            while (!done)
            {
                state->selectedPlanet = state->selectedPlanet + in.inX[0];
                if (state->selectedPlanet < 0)
                {
                    state->selectedPlanet = 4;
                }
                else if (state->selectedPlanet >= 5)
                {
                    state->selectedPlanet = 0;
                }
                done = 1;
            }
            pauseMenuSetupTitle(WORLDPLANET_SELECT_TITLE_TEXT_ID, gWorldPlanetTitleStringIds[state->selectedPlanet],
                                0x19, 0);
            /* obj->userData1 is the GameObject's generic per-instance state word
             * (its meaning is per-DLL); worldplanet uses it as a one-shot latch:
             * 0 until the first selection has been set up, 1 thereafter. This
             * block runs on a real selection change OR that first frame, but the
             * camera swoosh (releaseAction) + select SFX below are gated on the
             * latch so they fire only on genuine changes, not on the initial open. */
            if (prevPlanet != state->selectedPlanet || (obj)->userData1 == 0)
            {
                if ((obj)->userData1 != 0)
                {
                    objId = tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, 1);
                    Sfx_PlayFromObject(0, SFXTRIG_crf_babyambi3);
                }
                gWorldPlanetPathProgress = 0.0f;
                {
                    GameObject* planetObj =
                        ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[prevPlanet]]);
                    ((WorldObjState*)planetObj->extra)->effectState = 0;
                    planetObj = ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                    ((WorldObjState*)planetObj->extra)->effectState = 1;
                }
                (obj)->userData1 = 1;
            }
        }
        gWorldPlanetPathProgress = gWorldPlanetPathProgress + gWorldPlanetPathProgressStep;
        if (gWorldPlanetPathProgress >= gWorldPlanetPathProgressMax)
        {
            gWorldPlanetPathProgress = 0.0f;
        }
        for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++)
        {
            GameObject* planet = ObjList_FindObjectById(tbl[2][i]);
            WorldObjState* pstate = planet->extra;
            planet->anim.rotY = (obj)->anim.rotY;
            planet->anim.rotX = (obj)->anim.rotX;
            if ((u8)state->selectionLocked != 0 || (((int)(u32)state->unlockedPlanetMask >> i) & 1) == 0)
            {
                pstate->effectState = 0;
                if ((int)i == state->selectedPlanet)
                {
                    arwing->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
            else
            {
                if ((int)i == state->selectedPlanet)
                {
                    u32 fi = (int)gWorldPlanetPathProgress & 0xff;
                    u32 ni = (fi + 2) & 0xff;
                    f32 frac = gWorldPlanetPathProgress - fi;
                    WorldObjPathSegmentWork* segment = WorldObj_GetPathSegmentWork(pstate, fi);
                    f32 x0 = segment->start.x;
                    f32 x1 = segment->end.x;
                    f32 y0 = segment->start.y;
                    f32 y1 = segment->end.y;
                    f32 z0 = segment->start.z;
                    f32 z1 = segment->end.z;
                    s16 yaw;
                    s16 dyaw;
                    pstate->effectState = 2;
                    yaw = getAngle(x1 - x0, z1 - z0);
                    if (ni >= 0x16)
                    {
                        dyaw = yaw;
                    }
                    else
                    {
                        WorldObjPathSegmentWork* nextSegment = WorldObj_GetPathSegmentWork(pstate, ni);
                        dyaw = getAngle(nextSegment->start.x - x1, nextSegment->start.z - z1);
                    }
                    dyaw = dyaw - (u16)yaw;
                    if (dyaw > 0x8000)
                    {
                        dyaw = (s16)(dyaw - 0xffff);
                    }
                    if (dyaw < -0x8000)
                    {
                        dyaw = (s16)(dyaw + 0xffff);
                    }
                    if (getWorldMapVoiceoverTimer() != 0)
                    {
                        arwing->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    }
                    else
                    {
                        arwing->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
                    }
                    arwing->anim.rotX = (frac * dyaw + yaw);
                    arwing->anim.localPosX = frac * (x1 - x0) + x0;
                    arwing->anim.localPosY = frac * (y1 - y0) + y0;
                    arwing->anim.localPosZ = frac * (z1 - z0) + z0;
                }
                else
                {
                    pstate->effectState = 1;
                }
            }
        }
        objId = (int)ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
        if (getLoadedFileFlags(0) == 0 && gWorldPlanetInputLockTimer == 0)
        {
            switch ((u8)state->selectionLocked)
            {
            case 0:
                if (gWorldPlanetReselectDelayTimer != 0)
                {
                    gWorldPlanetReselectDelayTimer -= 1;
                }
                else
                {
                    if (gWorldPlanetSelectConfirmTimer == 0 &&
                        (state->unlockedPlanetMask & (1 << state->selectedPlanet)) != 0 &&
                        (buttons & PAD_BUTTON_A) != 0)
                    {
                        gWorldPlanetSelectConfirmTimer = 10;
                        mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                    }
                }
                if (gWorldPlanetSelectConfirmTimer != 0)
                {
                    Pause_ResetMenuFrameCounter();
                    gWorldPlanetSelectConfirmTimer -= 1;
                    if (gWorldPlanetSelectConfirmTimer <= 1)
                    {
                        gWorldPlanetSelectConfirmTimer = 0;
                        Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                        (*gCameraInterface)->setFocus((void*)objId, 0x50);
                        state->selectionLocked = 1;
                        (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
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
                {
                    int neq = lbl_803DDD00 != 0.0f;
                    neq = !neq;
                    if (neq)
                    {
                        lbl_803DDD00 = 1.0f;
                    }
                }
                if ((buttons & PAD_BUTTON_B) != 0)
                {
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_greatfox_lp);
                    streamFn_8000a380(2, 2, 1000);
                    (*gCameraInterface)->setFocus((void*)obj, 0x50);
                    state->selectionLocked = 0;
                    gWorldPlanetReselectDelayTimer = 0x1e;
                    (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
                    unlockLevel(gWorldPlanetLoadedMapId, 1, 0);
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                    gWorldPlanetInputLockTimer = 10;
                }
                else if ((buttons & PAD_BUTTON_A) != 0)
                {
                    (*gScreenTransitionInterface)->start(4, 1);
                    streamFn_8000a380(3, 1, 0);
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                    setShowWorldMapHud(0);
                    gWorldPlanetExitWarpTimer = 5;
                    lbl_803DDD10 = 0;
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_PRELOAD_FLAG);
                }
                break;
            }
        }
        else
        {
            Pause_ResetMenuFrameCounter();
        }
        {
            u32 ang;
            f32 r;
            {
                u8 spin = 0;
                ang = -(obj)->anim.rotZ & 0xffff;
                for (; spin < WORLDPLANET_PLANET_COUNT; spin++)
                {
                    GameObject* planetObj = ObjList_FindObjectById(tbl[2][spin]);
                    planetObj->anim.rotZ = -ang;
                }
            }
            for (b = 0, r = gWorldPlanetOrbitRadius; b < WORLDPLANET_PLANET_COUNT; b++)
            {
                GameObject* planetObj = ObjList_FindObjectById(tbl[0][b]);
                if (tbl[0][b] == WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID)
                {
                    planetObj->anim.rotX = ang + tbl[1][b] + 0x4000;
                }
                else
                {
                    planetObj->anim.rotX += 0x3c;
                }
                if (state->orbitSoundFrameCount > 2)
                {
                    Sfx_KeepAliveLoopedObjectSound((u32)planetObj, SFXTRIG_crf_babyambi2);
                }
                planetObj->anim.localPosX =
                    r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fcos16Approx(3000) + (obj)->anim.localPosX;
                planetObj->anim.localPosY =
                    r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fsin16Approx(3000) + (obj)->anim.localPosY;
                planetObj->anim.localPosZ = r * fcos16Approx((ang + tbl[1][b]) & 0xffff) + (obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}

void worldplanet_readMapInput(GameObject* obj, u8* outX, u8* outY)
{
    WorldPlanetState* state = obj->extra;
    s8 stickX;
    s8 stickY;
    s8 resX;
    s8 resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(WORLDPLANET_SAVE_FILE_SLOT) == 0)
    {
        if (stickX < -WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickX >= -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resX = -1;
            state->stickXRepeatFrames = 0;
        }
        if (stickX > WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickX <= WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resX = 1;
            state->stickXRepeatFrames = 0;
        }
        if (stickY < -WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickY >= -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resY = -1;
            state->stickYRepeatFrames = 0;
        }
        if (stickY > WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickY <= WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resY = 1;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickY = stickY;
        if (state->prevStickY < -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            state->stickYRepeatFrames++;
        }
        else if (state->prevStickY > WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            state->stickYRepeatFrames++;
        }
        else
        {
            state->stickYRepeatFrames = 0;
        }
        if (state->stickYRepeatFrames > WORLDPLANET_INPUT_REPEAT_FRAMES)
        {
            state->prevStickY = 0;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickX = stickX;
        if (state->prevStickX < -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            state->stickXRepeatFrames++;
        }
        else if (state->prevStickX > WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            state->stickXRepeatFrames++;
        }
        else
        {
            state->stickXRepeatFrames = 0;
        }
        if (state->stickXRepeatFrames > WORLDPLANET_INPUT_REPEAT_FRAMES)
        {
            state->prevStickX = 0;
            state->stickXRepeatFrames = 0;
        }
        *(s8*)outX = resX;
        *(s8*)outY = resY;
    }
    else
    {
        *outX = 0;
        *outY = 0;
    }
}

void worldplanet_init(GameObject* obj)
{
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
    for (; z[2] < WORLDPLANET_PLANET_COUNT; z[2]++)
    {
        if (mainGetBit(gWorldPlanetGameBitTable[z[2]]) != 0)
        {
            z[0] = 1;
            if (gWorldPlanetHintFlagTable[z[2]] != 0)
            {
                if ((s32)getNextTaskHintText() > WORLDPLANET_HINT_UNLOCK_THRESHOLD)
                {
                    z[0] = 0;
                }
            }
            if ((u8)z[0] != 0)
            {
                z[1] |= 1 << z[2];
            }
        }
    }
    state->unlockedPlanetMask = z[1];
    if (gWorldPlanetSavedSelection != -1)
    {
        state->selectedPlanet = gWorldPlanetSavedSelection;
    }
    else
    {
        for (j = 0; j < WORLDPLANET_PLANET_COUNT; j++)
        {
            if (mainGetBit(gWorldPlanetGameBitTable[gWorldPlanetDefaultSelectOrder[j]]) != 0)
            {
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
    (*gMapEventInterface)->savePoint((int)&obj->anim.localPosX, 0, 0, layer);
    (*gScreenTransitionInterface)->step(0x1e, 1);
    gWorldPlanetInputLockTimer = WORLDPLANET_COUNTDOWN_FRAMES;
    mainSetBits(gWorldPlanetGameBitTable[WORLDPLANET_SLOT_DINOSAUR_PLANET], 1);
    state->foxSpawnTimer = WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES;
    envFxActFn_800887f8(0);
}

void worldplanet_release(void)
{
}

void worldplanet_initialise(void)
{
}

/* Per-WorldPlanetSlot parameter table. Columns are WorldPlanetSlot 0..4
 * (Walled City / CloudRunner / Dinosaur / Dragon Rock / DarkIce). Declared
 * [3][5], but worldplanet_update also indexes tbl[3]: gWorldPlanetGameBitTable
 * is laid out immediately after this in .data, so tbl[3] intentionally walks
 * into it (the per-slot unlock gamebits - the contiguous 4th row).
 *   row 0: the orbiting island objects. Each frame they are placed on the orbit
 *          ring (localPos from orbit radius + the row-1 angle) and spun; they are
 *          also the camera's focus/action target on select & confirm and carry
 *          the binary selection highlight (WorldObjState.effectState 0/1). Slot
 *          2's entry is WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID (special-cased in the
 *          orbit placement).
 *   row 1: orbit ANGLE OFFSETS, not object ids - 0/0x4000/0x5FA0/0x8000/0xC000
 *          (0/90/~135/180/270 deg) spacing the islands evenly around the ring.
 *   row 2: per-slot objects that rotate with the map and each hold the flight
 *          PATH for one destination. When a planet is selected the small ferry
 *          Arwing (WORLDPLANET_ARWING_OBJECT_ID) is interpolated along the
 *          selected slot's path each frame; effectState
 *          = locked(0) / available(1) / selected(2). Verified live that all five
 *          routes exist - the Arwing is just unlock-gated (the effectState-0 branch
 *          hides it), so in normal play only the reachable planet's is ever seen. */
int gWorldPlanetObjectIdTable[3][5] = {
    /* row 0: orbiting island objects  */ {0x00042FEA, 0x00042FE8, 0x0004300D, 0x00042FE9, 0x00042FEB},
    /* row 1: orbit angle offsets      */ {0x00000000, 0x00004000, 0x00005FA0, 0x00008000, 0x0000C000},
    /* row 2: Arwing flight-path objs  */ {0x00043099, 0x00042FFF, 0x0004309A, 0x00043098, 0x00043097},
};

/* descriptor/ptr table auto 0x8032a1c8-0x8032a200 */
ObjectDescriptor gWorldPlanetObjDescriptor = {
    0x00000000,
    0x00000000,
    0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)worldplanet_initialise,
    (ObjectDescriptorCallback)worldplanet_release,
    0x00000000,
    (ObjectDescriptorCallback)worldplanet_init,
    (ObjectDescriptorCallback)worldplanet_update,
    (ObjectDescriptorCallback)worldplanet_hitDetect,
    (ObjectDescriptorCallback)worldplanet_render,
    (ObjectDescriptorCallback)worldplanet_free,
    (ObjectDescriptorCallback)worldplanet_getObjectTypeId,
    worldplanet_getExtraSize,
};
