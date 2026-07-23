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

extern int gWorldPlanetSelectConfirmTimer;
extern u8 gWorldPlanetExitWarpTimer;
extern s16 gWorldPlanetInputLockTimer;
extern int gWorldPlanetLoadedMapId;
extern f32 gWorldPlanetPathProgress;

void worldplanet_readMapInput(GameObject* obj, s8* outX, s8* outY)
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
        *outX = resX;
        *outY = resY;
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
