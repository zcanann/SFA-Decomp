/*
 * dbsh_shrine (DLL 0x195) - a rising Krazoa-shrine object in the
 * "dbshrine" map (mapId 43, a Krazoa spirit shrine). Idle until the map-event trigger
 * fires, it raises the spirit-vision sky and env fx, plays an idle sfx on
 * a randomised timer, then steps a small state machine
 * (WAITING -> RISING -> ACTIVE -> CLOSING -> RESET) gated by the
 * DBSH_SHRINE_GB_* game bits. The sequence callback DBSH_Shrine_SeqFn drives
 * level/map unlocks and toggles the attached point light.
 */
#include "main/dll/dll_0195_dbshshrine.h"
#include "main/vecmath_distance_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/player_api.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/sky_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/model_light.h"
#include "main/vecmath.h"
#include "main/render_envfx_api.h"
#include "main/objseq.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/audio/sfx.h"
#include "main/object_api.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/audio/music_trigger_ids.h"

#define DBSHSHRINE_OBJGROUP   0xb
#define DBSHSHRINE_MAP_SHRINE 0xb

#define DBSH_SHRINE_STATE_WAITING 0
#define DBSH_SHRINE_STATE_RISING  1
#define DBSH_SHRINE_STATE_ACTIVE  2
#define DBSH_SHRINE_STATE_CLOSING 4
#define DBSH_SHRINE_STATE_RESET   5

#define DBSH_SHRINE_OBJ_FLAG_ACTIVE    0x4000
#define DBSH_SHRINE_MAP_FLAG_TRIGGERED 0x1

#define DBSH_SHRINE_GB_APPROACH    0xdd3
#define DBSH_SHRINE_GB_FIRST_RISE  0x15f
#define DBSH_SHRINE_GB_RISE_DONE   0x16a
#define DBSH_SHRINE_GB_CLOSE_A     0x16b
#define DBSH_SHRINE_GB_CLOSE_B     0x16c
#define DBSH_SHRINE_GB_RESET_A     0xc72
#define DBSH_SHRINE_GB_RESET_B     0xc73
#define DBSH_SHRINE_GB_SCENE_BLOCK 0xcbb
#define DBSH_SHRINE_GB_ACTIVE      0xefa
#define DBSH_SHRINE_GB_INITIALIZED 0xf08

#define DBSH_SHRINE_ENVFX_A  0xd4
#define DBSH_SHRINE_ENVFX_B  0xd5
#define DBSH_SHRINE_ENVFX_C  0x222
#define DBSH_SHRINE_IDLE_SFX 0x343

#define OBJECT_TRIGGER_REFRESH(triggerId, obj, arg) (*gObjectTriggerInterface)->runSequence((triggerId), (obj), (arg))
#define MAP_EVENT_GET_ANIM(mapId, eventId)          (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))

__declspec(section ".sdata2") f32 lbl_803E50A0 = 512.0f;
__declspec(section ".sdata2") f32 lbl_803E50A4 = 128.0f;
__declspec(section ".sdata2") f32 lbl_803E50A8 = 192.0f;
__declspec(section ".sdata2") f32 lbl_803E50AC = 20.0f;
__declspec(section ".sdata2") f32 gEcShCupPi = 3.1415927f;
__declspec(section ".sdata2") f32 gEcShCupAngleToRadDivisor = 32768.0f;
__declspec(section ".sdata2") f32 lbl_803E50B8 = 600.0f;
__declspec(section ".sdata2") f32 lbl_803E50BC = 0.005f;
__declspec(section ".sdata2") f32 lbl_803E50C0 = 12.0f;
__declspec(section ".sdata2") f32 lbl_803E50C4 = 30.0f;
__declspec(section ".sdata2") f32 lbl_803E50C8 = 255.0f;

#pragma dont_inline on
void fn_801C8B68(int obj)
{
    register int self = obj;
    register int state2 = *(int*)&((GameObject*)self)->anim.placementData;
    register int state = *(int*)&((GameObject*)self)->extra;
    GameObject* player = Obj_GetPlayerObject();
    ObjAnimEventList local_var;
    f32 dist;
    f32 angA, angB;
    int delta;

    if ((((GameObject*)self)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        ((GameObject*)self)->anim.rotX = 0;
        ((GameObject*)self)->anim.localPosY = *(float*)(state2 + 0xc);
        return;
    }

    *(short*)(state + 0xe) = (short)((int)*(short*)(state + 0xe) + (int)(lbl_803E50A0 * timeDelta));
    *(short*)(state + 0x10) = (short)((int)*(short*)(state + 0x10) + (int)(lbl_803E50A4 * timeDelta));
    *(short*)(state + 0x12) = (short)((int)*(short*)(state + 0x12) + (int)(lbl_803E50A8 * timeDelta));

    ((GameObject*)self)->anim.localPosY =
        lbl_803E50AC + (*(float*)(state2 + 0xc) +
                        mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor));
    angA = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0x10)) / gEcShCupAngleToRadDivisor);
    angB = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor);
    angB = angB + angA;
    *(s16*)&((GameObject*)self)->anim.rotZ = (lbl_803E50B8 * angB);
    angA = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0x12)) / gEcShCupAngleToRadDivisor);
    angB = mathSinf((gEcShCupPi * (f32)(s32) * (short*)(state + 0xe)) / gEcShCupAngleToRadDivisor);
    angB = angB + angA;
    *(s16*)&((GameObject*)self)->anim.rotY = (lbl_803E50B8 * angB);

    ObjAnim_AdvanceCurrentMove(self, lbl_803E50BC, timeDelta,
                                                                 (ObjAnimEventList*)&local_var);

    if (player == NULL)
        return;

    {
        float dx = ((GameObject*)self)->anim.worldPosX - player->anim.worldPosX;
        float dz = ((GameObject*)self)->anim.worldPosZ - player->anim.worldPosZ;
        int ang = (u16)getAngle(dx, dz);
        delta = ang - (int)(u16)((GameObject*)self)->anim.rotX;
        if (delta > 0x8000)
            delta -= 0xffff;
        if (delta < -0x8000)
            delta += 0xffff;
        ((GameObject*)self)->anim.rotX =
            (short)((int)*(s16*)(int)(GameObject*)self + (int)((f32)delta * timeDelta / lbl_803E50C0));
    }
    dist = Vec_xzDistance((f32*)((u8*)self + 24), &player->anim.worldPosX);
    if (dist <= lbl_803E50C4)
    {
        ((GameObject*)self)->anim.alpha = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    }
    else
    {
        ((GameObject*)self)->anim.alpha = 0xff;
    }
}
#pragma dont_inline reset

__declspec(section ".sdata2") f32 lbl_803E50D8 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E50DC = 0.0f;
#pragma explicit_zero_data reset

int DBSH_Shrine_SeqFn(int obj, u32 unused, ObjAnimUpdateState* animUpdate)
{
    DbshShrineRuntime* runtime;
    int player;
    int i;
    u32 event;

    runtime = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        if (event != 0)
        {
            switch (event)
            {
            case 3:
                runtime->flags.latchStarted = 1;
                break;
            case 7:
                objSetAnimStateFlags((GameObject*)player, 2, 1);
                mainSetBits(DBSH_SHRINE_GB_FIRST_RISE, 1);
                mainSetBits(GAMEBIT_ITEM_SpiritTestStrength_Got, 1);
                (*gMapEventInterface)->setMapAct(DBSHSHRINE_MAP_SHRINE, 3);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            case 0xe:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled(runtime->light, 0, lbl_803E50D8);
                }
                break;
            case 0xf:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled(runtime->light, 0, lbl_803E50D8);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }

    return 0;
}

int dbsh_shrine_getExtraSize(void)
{
    return sizeof(DbshShrineRuntime);
}

int dbsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void dbsh_shrine_free(GameObject* obj)
{
    DbshShrineRuntime* runtime;

    runtime = (obj)->extra;
    if (runtime->light != NULL)
    {
        ModelLightStruct_free(runtime->light);
        runtime->light = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject((int)obj, DBSHSHRINE_OBJGROUP);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    Music_Trigger(MUSICTRIG_test_of_fear, 0);
    mainSetBits(DBSH_SHRINE_GB_ACTIVE, 0);
    mainSetBits(DBSH_SHRINE_GB_SCENE_BLOCK, 1);
}

void dbsh_shrine_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible)
{
    DbshShrineRuntime* runtime;

    runtime = (obj)->extra;
    if (visible == 0)
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled(runtime->light, 0, lbl_803E50D8);
        }
    }
    else
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled(runtime->light, 1, lbl_803E50D8);
        }
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E50D8);
        objParticleFn_80099d84((GameObject*)obj, lbl_803E50D8, 7, *(f32*)&lbl_803E50D8,
                               (ModelLightStruct*)runtime->light);
    }
}

void dbsh_shrine_hitDetect(void)
{
}

void dbsh_shrine_update(DbshShrineObject* obj)
{
    int player;
    u8 active;
    DbshShrineRuntime* runtime;

    runtime = obj->runtime;
    player = (int)Obj_GetPlayerObject();
    if ((void*)player == NULL)
    {
        return;
    }

    if (obj->introDelay != 0)
    {
        obj->introDelay--;
        if (obj->introDelay == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxActVoid(obj, player, DBSH_SHRINE_ENVFX_A, 0);
            getEnvfxActVoid(obj, player, DBSH_SHRINE_ENVFX_B, 0);
            getEnvfxActVoid(obj, player, DBSH_SHRINE_ENVFX_C, 0);
        }
    }

    fn_801C8B68((int)obj);
    SCGameBitLatch_Update(&runtime->latch, 2, -1, -1, DBSH_SHRINE_GB_APPROACH, 0xe);
    SCGameBitLatch_UpdateInverted(&runtime->latch, 1, -1, -1, DBSH_SHRINE_GB_SCENE_BLOCK, 8);
    SCGameBitLatch_Update(&runtime->latch, 4, -1, -1, DBSH_SHRINE_GB_SCENE_BLOCK, 0xc4);

    switch (runtime->state)
    {
    case DBSH_SHRINE_STATE_WAITING:
        obj->flags &= ~DBSH_SHRINE_OBJ_FLAG_ACTIVE;
        {
            f32 idleSfxTimer = runtime->idleSfxTimer - timeDelta;
            runtime->idleSfxTimer = idleSfxTimer;
            if (idleSfxTimer <= lbl_803E50DC)
            {
                Sfx_PlayFromObject((u32)obj, DBSH_SHRINE_IDLE_SFX);
                runtime->idleSfxTimer = (f32)(int)randomGetRange(500, 1000);
            }
        }
        if ((obj->mapFlags & DBSH_SHRINE_MAP_FLAG_TRIGGERED) != 0)
        {
            active = MAP_EVENT_GET_ANIM(obj->mapId, 1);
            if (active != 0)
            {
                MAP_EVENT_SET_ANIM(obj->mapId, 1, 0);
            }
            runtime->state = DBSH_SHRINE_STATE_RISING;
            mainSetBits(DBSH_SHRINE_GB_APPROACH, 1);
            obj->triggerRadius = 0x7fff;
            OBJECT_TRIGGER_REFRESH(0, obj, -1);
            Music_Trigger(MUSICTRIG_DIM_Snow, 1);
        }
        break;
    case DBSH_SHRINE_STATE_RISING:
        obj->flags |= DBSH_SHRINE_OBJ_FLAG_ACTIVE;
        if (runtime->flags.latchStarted != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_ACTIVE;
            mainSetBits(DBSH_SHRINE_GB_RISE_DONE, 1);
        }
        break;
    case DBSH_SHRINE_STATE_ACTIVE:
        if (mainGetBit(DBSH_SHRINE_GB_CLOSE_A) != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_CLOSING;
            runtime->resetTimer = 0;
        }
        else if (mainGetBit(DBSH_SHRINE_GB_CLOSE_B) != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_RESET;
            mainSetBits(DBSH_SHRINE_GB_RESET_A, 1);
            runtime->resetTimer = 10;
        }
        break;
    case DBSH_SHRINE_STATE_CLOSING:
        runtime->state = DBSH_SHRINE_STATE_RESET;
        audioStopByMask(3);
        OBJECT_TRIGGER_REFRESH(1, obj, -1);
        mainSetBits(DBSH_SHRINE_GB_APPROACH, 0);
        break;
    case DBSH_SHRINE_STATE_RESET:
        runtime->state = DBSH_SHRINE_STATE_WAITING;
        runtime->flags.latchStarted = 0;
        runtime->resetTimer = 0;
        mainSetBits(DBSH_SHRINE_GB_APPROACH, 0);
        mainSetBits(DBSH_SHRINE_GB_FIRST_RISE, 0);
        mainSetBits(DBSH_SHRINE_GB_RISE_DONE, 0);
        mainSetBits(DBSH_SHRINE_GB_CLOSE_A, 0);
        mainSetBits(DBSH_SHRINE_GB_CLOSE_B, 0);
        mainSetBits(DBSH_SHRINE_GB_RESET_A, 0);
        mainSetBits(DBSH_SHRINE_GB_RESET_B, 0);
        break;
    }
}

void dbsh_shrine_init(DbshShrineObject* obj)
{
    DbshShrineRuntime* runtime;

    runtime = obj->runtime;
    obj->messageFn = DBSH_Shrine_SeqFn;
    obj->triggerRadius = 0;
    runtime->state = DBSH_SHRINE_STATE_WAITING;
    runtime->flags.latchStarted = 0;
    runtime->resetTimer = 0;

    ObjMsg_AllocQueue(obj, 4);
    mainSetBits(DBSH_SHRINE_GB_FIRST_RISE, 0);

    if ((u8)MAP_EVENT_GET_ANIM(obj->mapId, 1) == 0)
    {
        MAP_EVENT_SET_ANIM(obj->mapId, 1, 1);
    }

    obj->startX = obj->x;
    obj->startY = obj->y;
    obj->startZ = obj->z;
    obj->introDelay = 1;

    if (runtime->light == 0)
    {
        runtime->light = objCreateLight(0, 1);
    }

    mainSetBits(DBSH_SHRINE_GB_ACTIVE, 1);
    mainSetBits(DBSH_SHRINE_GB_INITIALIZED, 1);
}

void dbsh_shrine_release(void)
{
}

void dbsh_shrine_initialise(void)
{
}
