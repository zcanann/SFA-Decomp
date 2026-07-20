/*
 * ccgasventcontrol - Crystal Caves gas-vent controller (DLL 0x0186). One
 * controller per gas room; the individual vents (ccgasvent, DLL 0x0185)
 * register in CCGASVENT_GROUP and this object supervises the whole group.
 *
 * Once all four vents exist and the room trigger (gameBit 0x3EC) fires it
 * runs the intro sequence, then enters the active state: it counts how many
 * vents the player is clear of (CCGasVentControlFn_801a9fd0), drives the air
 * meter and the rising heavy-fog gas, and - if the player sinks into the gas
 * - warps them back. Running the air out sets the "gas puzzle done" gameBit
 * (0xA3) and shuts everything down.
 *
 * The extra-state byte at +0 is the state-machine index (0..7).
 */
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/obj_group.h"
#include "main/gamebits.h"
#include "main/dll/CC/dll_0186_ccgasventcontrol.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin_api.h"
#include "main/object_descriptor.h"

/* Release camera back to the default gameplay mode (cameramode DLL 0x42). */
#define CCGASVENTCONTROL_CAMMODE_DEFAULT 0x42

#define CCGASVENTCONTROL_AIRMETER_BGTEXTURE 0x603 /* air-meter background texture id */

#define CCGASVENT_GROUP                  0x3f
#define CCGASVENTCONTROL_TARGET_OBJGROUP 5
#define GAMEBIT_GAS_ACTIVE               0x1c0 /* gas filling the room */
#define GAMEBIT_GAS_PUZZLE_DONE          0xa3
#define GAMEBIT_GAS_INTRO_TRIGGER        0x3ec /* fires the intro sequence once the vents exist */

#define CCGASVENTCONTROL_CLEAR_DISTANCE   100.0f
#define CCGASVENTCONTROL_SFX_VOLUME_MAX   127.0f
#define CCGASVENTCONTROL_RENDER_SCALE     1.0f
#define CCGASVENTCONTROL_AIR_METER_MAX    6000.0f
#define CCGASVENTCONTROL_FOG_RISE_MAX     50.0f
#define CCGASVENTCONTROL_AIR_RECOVERY     16.0f
#define CCGASVENTCONTROL_FOG_BELOW_OFFSET 15.0f
#define CCGASVENTCONTROL_FOG_DISTANCE     800.0f
#define CCGASVENTCONTROL_FOG_DENSITY      0.1f
#define CCGASVENTCONTROL_FOG_STEP         0.0005f
#define CCGASVENTCONTROL_AIR_METER_MIN    0.0f

/* extra-state byte (+0) state-machine index */
#define CCGASVENT_STATE_WAIT_VENTS 0 /* wait until all four vents exist */
#define CCGASVENT_STATE_WAIT_INTRO 1 /* vents ready; wait for room trigger, run intro seq */
#define CCGASVENT_STATE_INIT_METER 2 /* one-shot: init air meter and arm active gas */
#define CCGASVENT_STATE_ACTIVE     3 /* gas rising, air-meter drain/refill main loop */
#define CCGASVENT_STATE_WARP_BACK  4 /* player drowned; restart-point warp */
#define CCGASVENT_STATE_SAVE_POINT 5 /* puzzle solved; stamp a save point */
#define CCGASVENT_STATE_WAIT_CLEAR 6 /* wait for gas to clear, then shut fog off */
#define CCGASVENT_STATE_DONE       7 /* puzzle complete / inactive */

int CCGasVentControl_SeqFn(GameObject* obj)
{
    CCGasVentControlFn_801a9fd0(obj, obj->extra);
    return 0;
}

u8 CCGasVentControlFn_801a9fd0(GameObject* obj, CCGasVentControlState* state)
{
    u8 i;
    u8 count = 0;
    if (mainGetBit(GAMEBIT_GAS_ACTIVE) != 0)
    {
        int cnt;
        GameObject** vents = (GameObject**)ObjGroup_GetObjects(CCGASVENT_GROUP, &cnt);
        f32 thr;
        i = 0;
        thr = CCGASVENTCONTROL_CLEAR_DISTANCE;
        for (; i < 4; i++)
        {
            GameObject* nearest = (GameObject*)ObjGroup_FindNearestObject(
                CCGASVENTCONTROL_TARGET_OBJGROUP, vents[i], 0);
            if (getXZDistance(&vents[i]->anim.worldPosX, &nearest->anim.worldPosX) > thr)
            {
                count = count + 1u;
            }
        }
    }
    if (count != 0)
    {
        if (state->soundActive == 0)
        {
            Sfx_AddLoopedObjectSound((int)obj, SFXTRIG_en_diallp_c_223);
            state->soundActive = 1;
        }
        Sfx_SetObjectSfxVolume((int)obj, SFXTRIG_en_diallp_c_223, (u8)(count * 0xf + 0x28),
                               CCGASVENTCONTROL_SFX_VOLUME_MAX);
    }
    else
    {
        if (state->soundActive != 0)
        {
            Sfx_RemoveLoopedObjectSound((int)obj, SFXTRIG_en_diallp_c_223);
            state->soundActive = 0;
        }
    }
    return count;
}

int ccgasventcontrol_getExtraSize(void)
{
    return sizeof(CCGasVentControlState);
}

void ccgasventcontrol_free(GameObject* obj)
{
    CCGasVentControlState* state = obj->extra;
    u8 t = state->state;
    if (t == CCGASVENT_STATE_ACTIVE || t == CCGASVENT_STATE_WARP_BACK)
    {
        disableHeavyFog();
    }
    (*gGameUIInterface)->airMeterSetShutdown();
}

void ccgasventcontrol_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, CCGASVENTCONTROL_RENDER_SCALE);
}

void ccgasventcontrol_init(GameObject* obj, CCGasVentControlPlacement* placement);
void ccgasventcontrol_update(GameObject* obj);

ObjectDescriptor gCCgasventControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ccgasventcontrol_init,
    (ObjectDescriptorCallback)ccgasventcontrol_update,
    0,
    (ObjectDescriptorCallback)ccgasventcontrol_render,
    (ObjectDescriptorCallback)ccgasventcontrol_free,
    0,
    ccgasventcontrol_getExtraSize,
};

void ccgasventcontrol_update(GameObject* obj)
{
    CCGasVentControlState* state = obj->extra;
    u8 clearVentCount = CCGasVentControlFn_801a9fd0(obj, state);
    switch (state->state)
    {
    case CCGASVENT_STATE_WAIT_VENTS:
    {
        int cnt;
        ObjGroup_GetObjects(CCGASVENT_GROUP, &cnt);
        if (cnt == 4)
        {
            state->state = CCGASVENT_STATE_WAIT_INTRO;
        }
        break;
    }
    case CCGASVENT_STATE_WAIT_INTRO:
        if (mainGetBit(GAMEBIT_GAS_INTRO_TRIGGER) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            state->state = CCGASVENT_STATE_INIT_METER;
        }
        break;
    case CCGASVENT_STATE_INIT_METER:
        (*gGameUIInterface)->initAirMeter(6000, CCGASVENTCONTROL_AIRMETER_BGTEXTURE);
        state->airMeter = CCGASVENTCONTROL_AIR_METER_MAX;
        state->state = CCGASVENT_STATE_ACTIVE;
        state->ventCount = clearVentCount;
        break;
    case CCGASVENT_STATE_ACTIVE:
        if (clearVentCount != 0)
        {
            GameObject* player = Obj_GetPlayerObject();
            state->fogRise = state->fogRise + timeDelta / CCGASVENTCONTROL_CLEAR_DISTANCE;
            if (state->fogRise > CCGASVENTCONTROL_FOG_RISE_MAX)
            {
                state->fogRise = CCGASVENTCONTROL_FOG_RISE_MAX;
            }
            if (player->anim.localPosY <= obj->anim.localPosY + state->fogRise)
            {
                state->airMeter = -(timeDelta * clearVentCount - state->airMeter);
            }
            else
            {
                state->airMeter = CCGASVENTCONTROL_AIR_RECOVERY * timeDelta + state->airMeter;
                if (state->airMeter > CCGASVENTCONTROL_AIR_METER_MAX)
                {
                    state->airMeter = CCGASVENTCONTROL_AIR_METER_MAX;
                }
            }
            enableHeavyFog(obj->anim.localPosY + state->fogRise,
                           obj->anim.localPosY - CCGASVENTCONTROL_FOG_BELOW_OFFSET,
                           CCGASVENTCONTROL_FOG_DISTANCE, CCGASVENTCONTROL_FOG_DENSITY,
                           CCGASVENTCONTROL_FOG_STEP, 0);
            if (state->airMeter >= CCGASVENTCONTROL_AIR_METER_MIN)
            {
                (*gGameUIInterface)->runAirMeter((int)state->airMeter);
            }
            else
            {
                (*gGameUIInterface)->airMeterSetShutdown();
                obj->anim.localPosX = player->anim.localPosX;
                obj->anim.localPosY = player->anim.localPosY;
                obj->anim.localPosZ = player->anim.localPosZ;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                (*gCameraInterface)->setMode(CCGASVENTCONTROL_CAMMODE_DEFAULT, 0, 1, 0, NULL, 0x1e, 0xff);
                state->state = CCGASVENT_STATE_WARP_BACK;
            }
            if (clearVentCount != state->ventCount)
            {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
                state->ventCount = clearVentCount;
            }
        }
        else
        {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            (*gGameUIInterface)->airMeterSetShutdown();
            mainSetBits(GAMEBIT_GAS_PUZZLE_DONE, 1);
            mainSetBits(0x620, 0);
            state->state = CCGASVENT_STATE_SAVE_POINT;
        }
        break;
    case CCGASVENT_STATE_WARP_BACK:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case CCGASVENT_STATE_SAVE_POINT:
    {
        GameObject* player = Obj_GetPlayerObject();
        (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
        state->state = CCGASVENT_STATE_WAIT_CLEAR;
        break;
    }
    case CCGASVENT_STATE_WAIT_CLEAR:
        if (mainGetBit(GAMEBIT_GAS_ACTIVE) == 0)
        {
            disableHeavyFog();
            state->state = CCGASVENT_STATE_DONE;
        }
        break;
    }
}

void ccgasventcontrol_init(GameObject* obj, CCGasVentControlPlacement* placement)
{
    CCGasVentControlState* state = obj->extra;
    obj->animEventCallback = CCGasVentControl_SeqFn;
    obj->anim.rotX = (s16)((u32)placement->rotX << 8);
    if (mainGetBit(GAMEBIT_GAS_PUZZLE_DONE) != 0)
    {
        state->state = CCGASVENT_STATE_DONE;
    }
}
