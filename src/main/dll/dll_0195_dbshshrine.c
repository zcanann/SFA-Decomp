#include "main/dll/dll_0195_dbshshrine.h"
#include "main/objseq.h"

#define DBSH_SHRINE_STATE_WAITING 0
#define DBSH_SHRINE_STATE_RISING 1
#define DBSH_SHRINE_STATE_ACTIVE 2
#define DBSH_SHRINE_STATE_CLOSING 4
#define DBSH_SHRINE_STATE_RESET 5

#define DBSH_SHRINE_OBJ_FLAG_ACTIVE 0x4000
#define DBSH_SHRINE_MAP_FLAG_TRIGGERED 0x1

#define DBSH_SHRINE_GB_APPROACH 0xdd3
#define DBSH_SHRINE_GB_FIRST_RISE 0x15f
#define DBSH_SHRINE_GB_RISE_DONE 0x16a
#define DBSH_SHRINE_GB_CLOSE_A 0x16b
#define DBSH_SHRINE_GB_CLOSE_B 0x16c
#define DBSH_SHRINE_GB_RESET_A 0xc72
#define DBSH_SHRINE_GB_RESET_B 0xc73
#define DBSH_SHRINE_GB_SCENE_BLOCK 0xcbb

#define DBSH_SHRINE_ENVFX_A 0xd4
#define DBSH_SHRINE_ENVFX_B 0xd5
#define DBSH_SHRINE_ENVFX_C 0x222
#define DBSH_SHRINE_IDLE_SFX 0x343

typedef union SceneIntToDouble
{
    u64 bits;
    f64 value;
} SceneIntToDouble;

extern void skyFn_80088c94(int skyId, int enabled);
extern void getEnvfxAct(DbshShrineObject* obj, int target, int effectId, int flags);
extern void fn_801C8B68(DbshShrineObject * obj);
extern u32 GameBit_Get(u32 id);
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(DbshShrineObject* obj, int sfxId);
extern void Music_Trigger(int musicId, int value);
extern void audioStopByMask(int mask);
extern f32 timeDelta;
extern f32 lbl_803E50DC;

#define OBJECT_TRIGGER_REFRESH(triggerId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((triggerId), (obj), (arg))
#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))

void dbsh_shrine_update(DbshShrineObject* obj)
{
    extern void GameBit_Set(u32 id, u32 value);
    extern int randomGetRange(int min, int max);
    int player;
    int rand;
    u8 active;
    SceneIntToDouble randAsDouble;
    DbshShrineRuntime* runtime;

    runtime = obj->runtime;
    player = Obj_GetPlayerObject();
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
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_A, 0);
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_B, 0);
            getEnvfxAct(obj, player, DBSH_SHRINE_ENVFX_C, 0);
        }
    }

    fn_801C8B68(obj);
    SCGameBitLatch_Update(&runtime->latch, 2, -1, -1, DBSH_SHRINE_GB_APPROACH, 0xe);
    SCGameBitLatch_UpdateInverted(&runtime->latch, 1, -1, -1, DBSH_SHRINE_GB_SCENE_BLOCK, 8);
    SCGameBitLatch_Update(&runtime->latch, 4, -1, -1, DBSH_SHRINE_GB_SCENE_BLOCK, 0xc4);

    switch (runtime->state)
    {
    case DBSH_SHRINE_STATE_WAITING:
        obj->flags &= ~DBSH_SHRINE_OBJ_FLAG_ACTIVE;
        {
            f32 t = runtime->idleSfxTimer - timeDelta;
            runtime->idleSfxTimer = t;
            if (t <= lbl_803E50DC)
            {
                Sfx_PlayFromObject(obj, DBSH_SHRINE_IDLE_SFX);
                runtime->idleSfxTimer = (f32)(int)
                randomGetRange(500, 1000);
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
            GameBit_Set(DBSH_SHRINE_GB_APPROACH, 1);
            obj->triggerRadius = 0x7fff;
            OBJECT_TRIGGER_REFRESH(0, obj, -1);
            Music_Trigger(0xd8, 1);
        }
        break;
    case DBSH_SHRINE_STATE_RISING:
        obj->flags |= DBSH_SHRINE_OBJ_FLAG_ACTIVE;
        if (runtime->flags.latchStarted != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_ACTIVE;
            GameBit_Set(DBSH_SHRINE_GB_RISE_DONE, 1);
        }
        break;
    case DBSH_SHRINE_STATE_ACTIVE:
        if (GameBit_Get(DBSH_SHRINE_GB_CLOSE_A) != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_CLOSING;
            runtime->resetTimer = 0;
        }
        else if (GameBit_Get(DBSH_SHRINE_GB_CLOSE_B) != 0)
        {
            runtime->state = DBSH_SHRINE_STATE_RESET;
            GameBit_Set(DBSH_SHRINE_GB_RESET_A, 1);
            runtime->resetTimer = 10;
        }
        break;
    case DBSH_SHRINE_STATE_CLOSING:
        runtime->state = DBSH_SHRINE_STATE_RESET;
        audioStopByMask(3);
        OBJECT_TRIGGER_REFRESH(1, obj, -1);
        GameBit_Set(DBSH_SHRINE_GB_APPROACH, 0);
        break;
    case DBSH_SHRINE_STATE_RESET:
        runtime->state = DBSH_SHRINE_STATE_WAITING;
        runtime->flags.latchStarted = 0;
        runtime->resetTimer = 0;
        GameBit_Set(DBSH_SHRINE_GB_APPROACH, 0);
        GameBit_Set(DBSH_SHRINE_GB_FIRST_RISE, 0);
        GameBit_Set(DBSH_SHRINE_GB_RISE_DONE, 0);
        GameBit_Set(DBSH_SHRINE_GB_CLOSE_A, 0);
        GameBit_Set(DBSH_SHRINE_GB_CLOSE_B, 0);
        GameBit_Set(DBSH_SHRINE_GB_RESET_A, 0);
        GameBit_Set(DBSH_SHRINE_GB_RESET_B, 0);
        break;
    }
}

#include "main/game_object.h"

extern void ObjGroup_RemoveObject(int obj, int group);
extern void ModelLightStruct_free(int light);
extern void gameTimerStop(void);
extern void Music_Trigger(int id, int mode);
extern void unlockLevel(int param_1, int param_2, int param_3);
extern int mapGetDirIdx(int idx);
extern void lockLevel(int idx, int param_2);
extern void modelLightStruct_setEnabled(int light, int enabled, double scale);
extern void objRenderFn_8003b8f4(double scale, int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5);
extern void objParticleFn_80099d84(int obj, f32 scale, int kind, f32 fextra, int light);
extern void fn_80296518(int obj, int param_2, int param_3);

extern f32 lbl_803E50D8;

int fn_801C8EBC(int obj, undefined4 unused, ObjAnimUpdateState* animUpdate)
{
    extern void GameBit_Set(int eventId, int value);
    struct Creator1C6Flag15
    {
        u8 b80 : 1;
        u8 rest : 7;
    };
    void** state;
    int player;
    int i;
    u32 event;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;

    for (i = 0; i < (s32)animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        if (event != 0)
        {
            switch (event)
            {
            case 3:
                ((struct Creator1C6Flag15*)((u8*)state + 0x15))->b80 = 1;
                break;
            case 7:
                fn_80296518(player, 2, 1);
                GameBit_Set(0x15f, 1);
                GameBit_Set(0xc6e, 1);
                (*gMapEventInterface)->setMapAct(0xb, 3);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            case 0xe:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
                if (state[0] != NULL)
                {
                    modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
                }
                break;
            case 0xf:
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~0x4000);
                if (state[0] != NULL)
                {
                    modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
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
    return 0x18;
}

int dbsh_shrine_getObjectTypeId(void)
{
    return 0;
}

void dbsh_shrine_free(int obj)
{
    extern void GameBit_Set(int eventId, int value);
    void** state;

    state = ((GameObject*)obj)->extra;
    if (state[0] != NULL)
    {
        ModelLightStruct_free((int)state[0]);
        state[0] = NULL;
    }
    gameTimerStop();
    ObjGroup_RemoveObject(obj, 0xb);
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(8, 0);
    Music_Trigger(0xe, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
}

void dbsh_shrine_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, s8 visible)
{
    void** state;

    state = ((GameObject*)obj)->extra;
    if (visible == 0)
    {
        if (state[0] != NULL)
        {
            modelLightStruct_setEnabled((int)state[0], 0, (double)lbl_803E50D8);
        }
    }
    else
    {
        if (state[0] != NULL)
        {
            modelLightStruct_setEnabled((int)state[0], 1, (double)lbl_803E50D8);
        }
        ((void (*)(int, undefined4, undefined4, undefined4, undefined4, f32))objRenderFn_8003b8f4)(
            obj, p2, p3, p4, p5, lbl_803E50D8);
        objParticleFn_80099d84(obj, lbl_803E50D8, 7, *(f32*)&lbl_803E50D8, (int)state[0]);
    }
}

void dbsh_shrine_hitDetect(void)
{
}


#define DBSH_SHRINE_GB_FIRST_RISE 0x15f
#define DBSH_SHRINE_GB_ACTIVE 0xefa
#define DBSH_SHRINE_GB_INITIALIZED 0xf08

extern void ObjMsg_AllocQueue(DbshShrineObject* obj, int capacity);
extern void* objCreateLight(int obj, int lightType);

#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))

void dbsh_shrine_init(DbshShrineObject* obj)
{
    extern void GameBit_Set(u32 id, u32 value);
    DbshShrineRuntime* runtime;

    runtime = obj->runtime;
    obj->messageFn = fn_801C8EBC;
    obj->triggerRadius = 0;
    runtime->state = 0;
    runtime->flags.latchStarted = 0;
    runtime->resetTimer = 0;

    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(DBSH_SHRINE_GB_FIRST_RISE, 0);

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

    GameBit_Set(DBSH_SHRINE_GB_ACTIVE, 1);
    GameBit_Set(DBSH_SHRINE_GB_INITIALIZED, 1);
}

void dbsh_shrine_release(void)
{
}

void dbsh_shrine_initialise(void)
{
}
