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
#include "main/object_render_legacy.h"
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

typedef struct CcgasventcontrolState
{
    u8 state;       /* 0x00: state-machine index (0..7) */
    u8 soundActive; /* 0x01: looped vent-hiss sound latch (CCGasVentControlFn_801a9fd0) */
    u8 pad02[2];
    f32 airMeter; /* 0x04: air-meter value, depletes while submerged */
    f32 fogRise;  /* 0x08: rising gas/fog height above the vent */
    u8 ventCount; /* 0x0C: cached count of vents the player is clear of */
    u8 pad0D[3];
} CcgasventcontrolState;

STATIC_ASSERT(offsetof(CcgasventcontrolState, airMeter) == 0x4);
STATIC_ASSERT(offsetof(CcgasventcontrolState, fogRise) == 0x8);
STATIC_ASSERT(offsetof(CcgasventcontrolState, ventCount) == 0xC);
STATIC_ASSERT(sizeof(CcgasventcontrolState) == 0x10);

int CCGasVentControl_SeqFn(GameObject* obj)
{
    CCGasVentControlFn_801a9fd0((int)obj, *(int*)&(obj)->extra);
    return 0;
}

#pragma dont_inline on
u8 CCGasVentControlFn_801a9fd0(int obj, int extra)
{
    u8 i;
    u8 count = 0;
    if (mainGetBit(GAMEBIT_GAS_ACTIVE) != 0)
    {
        int cnt;
        int* list = (int*)ObjGroup_GetObjects(CCGASVENT_GROUP, &cnt);
        f32 thr;
        i = 0;
        thr = CCGASVENTCONTROL_CLEAR_DISTANCE;
        for (; i < 4; i++)
        {
            int other = ObjGroup_FindNearestObject(CCGASVENTCONTROL_TARGET_OBJGROUP, list[i], 0);
            if (getXZDistance((f32*)(list[i] + 0x18), (f32*)(other + 0x18)) > thr)
            {
                count = count + 1u;
            }
        }
    }
    if (count != 0)
    {
        if (((CcgasventcontrolState*)extra)->soundActive == 0)
        {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_en_diallp_c_223);
            ((CcgasventcontrolState*)extra)->soundActive = 1;
        }
        Sfx_SetObjectSfxVolume(obj, SFXTRIG_en_diallp_c_223, (u8)(count * 0xf + 0x28),
                               CCGASVENTCONTROL_SFX_VOLUME_MAX);
    }
    else
    {
        if (((CcgasventcontrolState*)extra)->soundActive != 0)
        {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_en_diallp_c_223);
            ((CcgasventcontrolState*)extra)->soundActive = 0;
        }
    }
    return count;
}
#pragma dont_inline reset

int ccgasventcontrol_getExtraSize(void)
{
    return sizeof(CcgasventcontrolState);
}

void ccgasventcontrol_free(GameObject* obj)
{
    char* inner = obj->extra;
    u8 t = ((CcgasventcontrolState*)inner)->state;
    if (t == CCGASVENT_STATE_ACTIVE || t == CCGASVENT_STATE_WARP_BACK)
    {
        disableHeavyFog();
    }
    (*gGameUIInterface)->airMeterSetShutdown();
}

void ccgasventcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, CCGASVENTCONTROL_RENDER_SCALE);
}

void ccgasventcontrol_init(GameObject* obj, u8* def);
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
    int ex = *(int*)&(obj)->extra;
    u8 b = CCGasVentControlFn_801a9fd0((int)obj, ex);
    switch (((CcgasventcontrolState*)ex)->state)
    {
    case CCGASVENT_STATE_WAIT_VENTS:
    {
        int cnt;
        ObjGroup_GetObjects(CCGASVENT_GROUP, &cnt);
        if (cnt == 4)
        {
            ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_WAIT_INTRO;
        }
        break;
    }
    case CCGASVENT_STATE_WAIT_INTRO:
        if (mainGetBit(GAMEBIT_GAS_INTRO_TRIGGER) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_INIT_METER;
        }
        break;
    case CCGASVENT_STATE_INIT_METER:
        (*gGameUIInterface)->initAirMeter(6000, CCGASVENTCONTROL_AIRMETER_BGTEXTURE);
        ((CcgasventcontrolState*)ex)->airMeter = CCGASVENTCONTROL_AIR_METER_MAX;
        ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_ACTIVE;
        ((CcgasventcontrolState*)ex)->ventCount = b;
        break;
    case CCGASVENT_STATE_ACTIVE:
        if (b != 0)
        {
            int player = (int)Obj_GetPlayerObject();
            ((CcgasventcontrolState*)ex)->fogRise =
                ((CcgasventcontrolState*)ex)->fogRise + timeDelta / CCGASVENTCONTROL_CLEAR_DISTANCE;
            if (((CcgasventcontrolState*)ex)->fogRise > CCGASVENTCONTROL_FOG_RISE_MAX)
            {
                ((CcgasventcontrolState*)ex)->fogRise = CCGASVENTCONTROL_FOG_RISE_MAX;
            }
            if (((GameObject*)player)->anim.localPosY <= (obj)->anim.localPosY + ((CcgasventcontrolState*)ex)->fogRise)
            {
                ((CcgasventcontrolState*)ex)->airMeter = -(timeDelta * b - ((CcgasventcontrolState*)ex)->airMeter);
            }
            else
            {
                ((CcgasventcontrolState*)ex)->airMeter =
                    CCGASVENTCONTROL_AIR_RECOVERY * timeDelta + ((CcgasventcontrolState*)ex)->airMeter;
                if (((CcgasventcontrolState*)ex)->airMeter > CCGASVENTCONTROL_AIR_METER_MAX)
                {
                    ((CcgasventcontrolState*)ex)->airMeter = CCGASVENTCONTROL_AIR_METER_MAX;
                }
            }
            enableHeavyFog((obj)->anim.localPosY + ((CcgasventcontrolState*)ex)->fogRise,
                           (obj)->anim.localPosY - CCGASVENTCONTROL_FOG_BELOW_OFFSET,
                           CCGASVENTCONTROL_FOG_DISTANCE, CCGASVENTCONTROL_FOG_DENSITY,
                           CCGASVENTCONTROL_FOG_STEP, 0);
            if (((CcgasventcontrolState*)ex)->airMeter >= CCGASVENTCONTROL_AIR_METER_MIN)
            {
                (*gGameUIInterface)->runAirMeter((int)((CcgasventcontrolState*)ex)->airMeter);
            }
            else
            {
                (*gGameUIInterface)->airMeterSetShutdown();
                (obj)->anim.localPosX = ((GameObject*)player)->anim.localPosX;
                (obj)->anim.localPosY = ((GameObject*)player)->anim.localPosY;
                (obj)->anim.localPosZ = ((GameObject*)player)->anim.localPosZ;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                (*gCameraInterface)->setMode(CCGASVENTCONTROL_CAMMODE_DEFAULT, 0, 1, 0, NULL, 0x1e, 0xff);
                ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_WARP_BACK;
            }
            if (b != ((CcgasventcontrolState*)ex)->ventCount)
            {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
                ((CcgasventcontrolState*)ex)->ventCount = b;
            }
        }
        else
        {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            (*gGameUIInterface)->airMeterSetShutdown();
            mainSetBits(GAMEBIT_GAS_PUZZLE_DONE, 1);
            mainSetBits(0x620, 0);
            ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_SAVE_POINT;
        }
        break;
    case CCGASVENT_STATE_WARP_BACK:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case CCGASVENT_STATE_SAVE_POINT:
    {
        int player = (int)Obj_GetPlayerObject();
        (*gMapEventInterface)->savePoint(player + 0xc, ((GameObject*)player)->anim.rotX, 1, 0);
        ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_WAIT_CLEAR;
        break;
    }
    case CCGASVENT_STATE_WAIT_CLEAR:
        if (mainGetBit(GAMEBIT_GAS_ACTIVE) == 0)
        {
            disableHeavyFog();
            ((CcgasventcontrolState*)ex)->state = CCGASVENT_STATE_DONE;
        }
        break;
    }
}

void ccgasventcontrol_init(GameObject* obj, u8* def)
{
    char* inner = obj->extra;
    obj->animEventCallback = CCGasVentControl_SeqFn;
    obj->anim.rotX = (s16)((u32)def[0x1a] << 8);
    if (mainGetBit(GAMEBIT_GAS_PUZZLE_DONE) != 0)
    {
        ((CcgasventcontrolState*)inner)->state = CCGASVENT_STATE_DONE;
    }
}
