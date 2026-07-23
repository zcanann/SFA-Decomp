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
#include "main/worldplanet_lighting.h"
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

#define WORLDPLANET_CAMMODE_WORLDMAP 0x4e /* cameramode DLL dll_004E_cameramodeworldmap */

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200

extern int gWorldPlanetSelectConfirmTimer;
extern u8 gWorldPlanetExitWarpTimer;
extern s16 gWorldPlanetInputLockTimer;
extern int gWorldPlanetLoadedMapId;
extern f32 gWorldPlanetPathProgress;

extern f32 lbl_803DDD00;
extern s16 gWorldPlanetReselectDelayTimer;
extern int lbl_803DDD10;

#include "main/fsin16_approx_api.h"
#include "main/fcos16_approx_api.h"
extern f32 gWorldPlanetPfxOffsetX;
extern f32 gWorldPlanetPfxOffsetY;
extern f32 gWorldPlanetPfxOffsetZ;
extern f32 gWorldPlanetPathProgressStep;
extern f32 gWorldPlanetPathProgressMax;
extern f32 gWorldPlanetOrbitRadius;

void worldplanet_update(GameObject* obj)
{
    u8 prevPlanet;
    GameObject* arwing;
    int buttons;
    WorldPlanetObjectTables* tbl;
    WorldPlanetState* state;
    u8 done;
    u8 i;
    u8 planetIdx;
    int objId;
    WorldObjEffectParams pfx;
    struct
    {
        s8 inY;
        s8 inX[3];
    } in;

    tbl = &gWorldPlanetObjectIdTable;
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
            setup->base.color[0] = ((ObjPlacement*)def)->color[0];
            setup->base.color[2] = ((ObjPlacement*)def)->color[2];
            setup->base.color[1] = ((ObjPlacement*)def)->color[1];
            setup->base.color[3] = ((ObjPlacement*)def)->color[3];
            setup->base.posX = (obj)->anim.localPosX;
            setup->base.posY = (obj)->anim.localPosY;
            setup->base.posZ = (obj)->anim.localPosZ;
            Obj_SetupObject((ObjPlacement*)setup, 5, (obj)->anim.mapEventSlot, -1, NULL);
        }
    }
    if (state->foxSpawnTimer < 0)
    {
        state->foxSpawnTimer = 0;
    }
    worldplanet_updateMapLighting(obj);
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
            objId = tbl->orbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]];
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
        worldplanet_readMapInput(obj, in.inX, &in.inY);
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
            /* The per-slot gamebit block immediately follows these object tables in retail data. */
            ids = (int*)(tbl + 1);
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
                    objId = tbl->orbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, 1);
                    Sfx_PlayFromObject(0, SFXTRIG_crf_babyambi3);
                }
                gWorldPlanetPathProgress = 0.0f;
                {
                    GameObject* planetObj =
                        ObjList_FindObjectById(tbl->orbitObjectIds[gWorldPlanetSelectionToIndex[prevPlanet]]);
                    ((WorldObjState*)planetObj->extra)->effectState = 0;
                    planetObj =
                        ObjList_FindObjectById(tbl->orbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
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
            GameObject* planet = ObjList_FindObjectById(tbl->flightPathObjectIds[i]);
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
        objId = (int)ObjList_FindObjectById(tbl->orbitObjectIds[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
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
                    Music_StopChannelsByPriorityGroup(2, MUSIC_CHANNEL_STOP_FADE, 1000);
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
                    Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_DEFAULT, 0);
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
            f32 orbitRadius;
            {
                u8 spin = 0;
                ang = -(obj)->anim.rotZ & 0xffff;
                for (; spin < WORLDPLANET_PLANET_COUNT; spin++)
                {
                    GameObject* planetObj = ObjList_FindObjectById(tbl->flightPathObjectIds[spin]);
                    planetObj->anim.rotZ = -ang;
                }
            }
            for (planetIdx = 0, orbitRadius = gWorldPlanetOrbitRadius; planetIdx < WORLDPLANET_PLANET_COUNT; planetIdx++)
            {
                GameObject* planetObj = ObjList_FindObjectById(tbl->orbitObjectIds[planetIdx]);
                if (tbl->orbitObjectIds[planetIdx] == WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID)
                {
                    planetObj->anim.rotX = ang + tbl->orbitAngleOffsets[planetIdx] + 0x4000;
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
                    orbitRadius * fsin16Approx((ang + tbl->orbitAngleOffsets[planetIdx]) & 0xffff) * fcos16Approx(3000) +
                    (obj)->anim.localPosX;
                planetObj->anim.localPosY =
                    orbitRadius * fsin16Approx((ang + tbl->orbitAngleOffsets[planetIdx]) & 0xffff) * fsin16Approx(3000) +
                    (obj)->anim.localPosY;
                planetObj->anim.localPosZ =
                    orbitRadius * fcos16Approx((ang + tbl->orbitAngleOffsets[planetIdx]) & 0xffff) + (obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}
