#include "main/audio/sfx.h"
#include "main/audio/music_api.h"
#include "main/render.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/object_api.h"

#define ObjList_FindObjectByIdLegacy(id) ((int (*)(int))ObjList_FindObjectById)(id)
#include "main/object.h"
#include "main/effect_interfaces.h"
#include "main/mapEvent.h"
#include "main/screen_transition.h"
#include "main/worldobj.h"
#include "main/worldplanet.h"
#include "main/pad.h"
#include "main/audio.h"
#include "main/lightmap.h"
#include "main/model.h"
#include "main/objprint_dolphin.h"
#include "main/rcp_dolphin.h"
#include "main/shader.h"
#include "main/sky_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui_api.h"

#define WORLDPLANET_CAMMODE_WORLDMAP 0x4e /* cameramode DLL dll_004E_cameramodeworldmap */

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
extern f32 lbl_803E6618;
/* unlock gamebit per WorldPlanetSlot: [0] Walled City, [1] CloudRunner,
 * [2] Dinosaur Planet (== WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, always set),
 * [3] Dragon Rock, [4] DarkIce Mines. */
int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT] = {1019, 1018, 2659, 1020, 1017};
extern u8 gWorldPlanetHintFlagTable[8];
extern u8 gWorldPlanetDefaultSelectOrder[8];
extern int gWorldPlanetSavedSelection;
extern int gWorldPlanetSelectConfirmTimer;
extern u8 gWorldPlanetExitWarpTimer;
extern s16 gWorldPlanetInputLockTimer;
extern int gWorldPlanetLoadedMapId;
extern f32 gWorldPlanetPathProgress;
extern f32 lbl_803E65F8;
extern u16 getNextTaskHintText(void);
extern void worldplanet_updateMapLighting(int obj);
extern void setFrameCountdown_800202c4(int frames);

extern void setIsOvercast(int v);
extern void pauseMenuSetupTitle(int strId, int p2, int p3, int p4);
extern f32 lbl_803DDD00;
extern s16 gWorldPlanetReselectDelayTimer;
extern int lbl_803DDD10;
extern int gWorldPlanetObjectIdTable[3][5]; /* [row][WorldPlanetSlot]; see definition for row meanings */
extern u8 gWorldPlanetSelectionToIndex[8];
extern u8 gWorldPlanetTitleStringIds[8];
/* per-planet mission-briefing speaker model (WorldMapBriefingSpeaker), indexed by WorldPlanetSlot */
extern u8 gWorldPlanetBriefingSpeakerModel[8];
extern u8 gWorldPlanetLoadMapIndices[6];
extern u8 gWorldPlanetWarpMapIndices[6];

extern float fsin16Approx(int angle);
extern float fcos16Approx(int angle);
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

void worldplanet_render(u32 obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int draw;

    draw = visible;
    if (draw != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6618);
    }
    return;
}

void worldplanet_hitDetect(void)
{
    return;
}

void worldplanet_release(void)
{
}

void worldplanet_initialise(void)
{
}

void worldplanet_init(GameObject* obj)
{
    WorldPlanetState* state;
    int z[2];
    int layer;
    int j;
    int flag;

    state = obj->extra;
    gWorldPlanetSelectConfirmTimer = 0;
    mainSetBits(WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, 1);
    z[0] = 0;
    z[1] = z[0];
    for (; z[1] < WORLDPLANET_PLANET_COUNT; z[1]++)
    {
        if (mainGetBit(gWorldPlanetGameBitTable[z[1]]) != 0)
        {
            flag = 1;
            if (gWorldPlanetHintFlagTable[z[1]] != 0)
            {
                if ((s32)getNextTaskHintText() > WORLDPLANET_HINT_UNLOCK_THRESHOLD)
                {
                    flag = 0;
                }
            }
            if ((u8)flag != 0)
            {
                z[0] |= 1 << z[1];
            }
        }
    }
    state->unlockedPlanetMask = z[0];
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
    gWorldPlanetPathProgress = lbl_803E65F8;
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

#pragma peephole on
void worldplanet_readMapInput(GameObject* obj, u8* outX, u8* outY)
{
    WorldPlanetState* state = obj->extra;
    int stickX;
    int stickY;
    s8 resX;
    s8 resY;

    stickX = padGetStickXInt(0);
    stickY = padGetStickYInt(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(WORLDPLANET_SAVE_FILE_SLOT) == 0)
    {
        if ((s8)stickX < -WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickX >= -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resX = -1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickX > WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickX <= WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resX = 1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickY < -WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickY >= -WORLDPLANET_INPUT_STICK_THRESHOLD)
        {
            resY = -1;
            state->stickYRepeatFrames = 0;
        }
        if ((s8)stickY > WORLDPLANET_INPUT_STICK_THRESHOLD && state->prevStickY <= WORLDPLANET_INPUT_STICK_THRESHOLD)
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
#pragma peephole reset

#pragma opt_lifetimes off
#pragma opt_loop_invariants off
#pragma opt_strength_reduction off
void worldplanet_update(GameObject* obj)
{
    u8 prevPlanet;
    int arwing;
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
            *(u8*)((char*)setup + 4) = *(u8*)(def + 4);
            *(u8*)((char*)setup + 6) = *(u8*)(def + 6);
            *(u8*)((char*)setup + 5) = *(u8*)(def + 5);
            *(u8*)((char*)setup + 7) = *(u8*)(def + 7);
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
                int briefingPortrait = ObjList_FindObjectByIdLegacy(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                ((WorldObjState*)((GameObject*)briefingPortrait)->extra)->controlByte =
                    gWorldPlanetBriefingSpeakerModel[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & WORLDPLANET_STATE_FLAG_ENVFX_STARTED) == 0)
        {
            state->flags |= WORLDPLANET_STATE_FLAG_ENVFX_STARTED;
            getEnvfxActInt(0, 0, WORLDPLANET_ENVFX_OPEN_ID, 0);
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
            int fox = ObjList_FindObjectByIdLegacy(WORLDPLANET_FOX_OBJECT_ID);
            ((GameObject*)fox)->anim.rotZ = (obj)->anim.rotZ;
            ((GameObject*)fox)->anim.rotY = (obj)->anim.rotY;
            ((GameObject*)fox)->anim.rotX = (obj)->anim.rotX;
        }
        arwing = ObjList_FindObjectByIdLegacy(WORLDPLANET_ARWING_OBJECT_ID);
        ((WorldObjState*)((GameObject*)arwing)->extra)->effectState = state->selectionLocked;
        prevPlanet = state->selectedPlanet;
        {
            u8 ok;
            int z[2];
            int* ids;
            u8* hints;
            z[0] = 0;
            z[1] = z[0];
            ids = tbl[3];
            hints = gWorldPlanetHintFlagTable;
            for (; z[1] < 5; z[1]++)
            {
                if (mainGetBit(*ids) != 0)
                {
                    ok = 1;
                    if (*hints != 0 && (s32)getNextTaskHintText() > 0xad)
                    {
                        ok = 0;
                    }
                    if (ok)
                    {
                        z[0] |= 1 << z[1];
                    }
                }
                ids += 1;
                hints += 1;
            }
            state->unlockedPlanetMask = z[0];
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
            /* obj->unkF4 is the GameObject's generic per-instance state word
             * (its meaning is per-DLL); worldplanet uses it as a one-shot latch:
             * 0 until the first selection has been set up, 1 thereafter. This
             * block runs on a real selection change OR that first frame, but the
             * camera swoosh (releaseAction) + select SFX below are gated on the
             * latch so they fire only on genuine changes, not on the initial open. */
            if (prevPlanet != state->selectedPlanet || (obj)->unkF4 == 0)
            {
                if ((obj)->unkF4 != 0)
                {
                    objId = tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, 1);
                    Sfx_PlayFromObject(0, SFXTRIG_crf_babyambi3);
                }
                gWorldPlanetPathProgress = lbl_803E65F8;
                {
                    int planetObj = ObjList_FindObjectByIdLegacy(tbl[0][gWorldPlanetSelectionToIndex[prevPlanet]]);
                    ((WorldObjState*)((GameObject*)planetObj)->extra)->effectState = 0;
                    planetObj = ObjList_FindObjectByIdLegacy(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                    ((WorldObjState*)((GameObject*)planetObj)->extra)->effectState = 1;
                }
                (obj)->unkF4 = 1;
            }
        }
        gWorldPlanetPathProgress = gWorldPlanetPathProgress + gWorldPlanetPathProgressStep;
        if (gWorldPlanetPathProgress >= gWorldPlanetPathProgressMax)
        {
            gWorldPlanetPathProgress = lbl_803E65F8;
        }
        for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++)
        {
            int planet = ObjList_FindObjectByIdLegacy(tbl[2][i]);
            WorldObjState* pstate = ((GameObject*)planet)->extra;
            ((GameObject*)planet)->anim.rotY = (obj)->anim.rotY;
            ((GameObject*)planet)->anim.rotX = (obj)->anim.rotX;
            if ((u8)state->selectionLocked != 0 || (((int)(u32)state->unlockedPlanetMask >> i) & 1) == 0)
            {
                pstate->effectState = 0;
                if ((int)i == state->selectedPlanet)
                {
                    ((GameObject*)arwing)->anim.flags = ((GameObject*)arwing)->anim.flags | OBJANIM_FLAG_HIDDEN;
                }
            }
            else
            {
                if ((int)i == state->selectedPlanet)
                {
                    u32 fi = (int)gWorldPlanetPathProgress & 0xff;
                    u32 ni = (fi + 2) & 0xff;
                    f32 frac = gWorldPlanetPathProgress - fi;
                    char* seg = WorldObj_GetPathPointWork(pstate, fi);
                    f32 x0 = *(f32*)(seg + 0x10);
                    f32 x1 = *(f32*)(seg + 0x28);
                    f32 y0 = *(f32*)(seg + 0x14);
                    f32 y1 = *(f32*)(seg + 0x2c);
                    f32 z0 = *(f32*)(seg + 0x18);
                    f32 z1 = *(f32*)(seg + 0x30);
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
                        char* nseg = WorldObj_GetPathPointWork(pstate, ni);
                        dyaw = getAngle(*(f32*)(nseg + 0x10) - x1, *(f32*)(nseg + 0x18) - z1);
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
                        ((GameObject*)arwing)->anim.flags = ((GameObject*)arwing)->anim.flags | OBJANIM_FLAG_HIDDEN;
                    }
                    else
                    {
                        ((GameObject*)arwing)->anim.flags = ((GameObject*)arwing)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
                    }
                    *(s16*)&((GameObject*)arwing)->anim.rotX = (frac * dyaw + yaw);
                    ((GameObject*)arwing)->anim.localPosX = frac * (x1 - x0) + x0;
                    ((GameObject*)arwing)->anim.localPosY = frac * (y1 - y0) + y0;
                    ((GameObject*)arwing)->anim.localPosZ = frac * (z1 - z0) + z0;
                }
                else
                {
                    pstate->effectState = 1;
                }
            }
        }
        objId = ObjList_FindObjectByIdLegacy(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
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
                            int briefingPortrait = ObjList_FindObjectByIdLegacy(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                            ((WorldObjState*)((GameObject*)briefingPortrait)->extra)->controlByte =
                                gWorldPlanetBriefingSpeakerModel[state->selectedPlanet];
                        }
                        gWorldPlanetLoadedMapId = loadMapAndParent(
                            gWorldPlanetLoadMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                        lockLevel(gWorldPlanetLoadedMapId, 1);
                        loadModelAndAnimTabs();
                        lbl_803DDD00 = lbl_803E65F8;
                        gWorldPlanetSavedSelection = state->selectedPlanet;
                    }
                }
                break;
            case 1:
                Pause_ResetMenuFrameCounter();
                {
                    int neq = lbl_803DDD00 != lbl_803E65F8;
                    neq = !neq;
                    if (neq)
                    {
                        lbl_803DDD00 = lbl_803E6618;
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
            b = 0;
            ang = -(obj)->anim.rotZ & 0xffff;
            for (; b < WORLDPLANET_PLANET_COUNT; b++)
            {
                int planetObj = ObjList_FindObjectByIdLegacy(tbl[2][b]);
                ((GameObject*)planetObj)->anim.rotZ = -ang;
            }
            for (b = 0, r = gWorldPlanetOrbitRadius; b < WORLDPLANET_PLANET_COUNT; b++)
            {
                s16* rotPtr = (s16*)ObjList_FindObjectById(tbl[0][b]);
                if (tbl[0][b] == WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID)
                {
                    *rotPtr = ang + tbl[1][b] + 0x4000;
                }
                else
                {
                    *rotPtr += 0x3c;
                }
                if (state->orbitSoundFrameCount > 2)
                {
                    Sfx_KeepAliveLoopedObjectSound((u32)rotPtr, SFXTRIG_crf_babyambi2);
                }
                *(f32*)(rotPtr + 6) =
                    r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fcos16Approx(3000) + (obj)->anim.localPosX;
                *(f32*)(rotPtr + 8) =
                    r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fsin16Approx(3000) + (obj)->anim.localPosY;
                *(f32*)(rotPtr + 10) = r * fcos16Approx((ang + tbl[1][b]) & 0xffff) + (obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}
#pragma opt_strength_reduction reset
#pragma opt_loop_invariants reset
#pragma opt_lifetimes reset

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
