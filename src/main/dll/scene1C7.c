#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/scene1C7.h"
#include "main/dll/SC/SCtotemlogpuz.h"

#define DBSH_SHRINE_STATE_WAITING 0
#define DBSH_SHRINE_STATE_RISING 1
#define DBSH_SHRINE_STATE_ACTIVE 2
#define DBSH_SHRINE_STATE_DONE 3
#define DBSH_SHRINE_STATE_CLOSING 4
#define DBSH_SHRINE_STATE_RESET 5

#define DBSH_SHRINE_OBJ_FLAG_ACTIVE 0x4000
#define DBSH_SHRINE_MAP_FLAG_TRIGGERED 0x1
#define DBSH_SHRINE_LATCH_STARTED 0x80

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

typedef struct DbshShrineRuntime {
    u8 pad00[4];
    SCGameBitLatchState latch;
    f32 idleSfxTimer;
    s16 resetTimer;
    u8 pad0E[6];
    u8 state;
    u8 flags;
} DbshShrineRuntime;

typedef struct DbshShrineObject {
    s16 triggerRadius;
    u8 pad02[4];
    s16 flags;
    u8 pad08[0xa4];
    s8 mapId;
    u8 padAD[2];
    u8 mapFlags;
    u8 padB0[8];
    DbshShrineRuntime *runtime;
    u8 padBC[0x38];
    s32 introDelay;
} DbshShrineObject;

typedef void (*ObjectTriggerRefreshFn)(int triggerId, DbshShrineObject *obj, int arg);

typedef union SceneIntToDouble {
    u64 bits;
    f64 value;
} SceneIntToDouble;

extern void skyFn_80088c94(int skyId, int enabled);
extern void getEnvfxAct(DbshShrineObject *obj, int target, int effectId, int flags);
extern void fn_801C8B68(DbshShrineObject *obj);
extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern int Obj_GetPlayerObject(void);
extern int randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(DbshShrineObject *obj, int sfxId);
extern void Music_Trigger(int musicId, int value);
extern void audioStopByMask(int mask);

extern int *gObjectTriggerInterface;
extern MapEventInterface **gMapEventInterface;
extern f32 timeDelta;
extern f32 lbl_803E50DC;
extern f64 lbl_803E50D0;

#define OBJECT_TRIGGER_REFRESH(triggerId, obj, arg) \
    ((ObjectTriggerRefreshFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))((triggerId), (obj), (arg))
#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    (*gMapEventInterface)->getAnimEvent((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))

/*
 * --INFO--
 *
 * Function: dbsh_shrine_update
 * EN v1.0 Address: 0x801C91B0
 * EN v1.0 Size: 916b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dbsh_shrine_update(DbshShrineObject *obj)
{
    int player;
    int rand;
    u8 active;
    SceneIntToDouble randAsDouble;
    DbshShrineRuntime *runtime;

    runtime = obj->runtime;
    player = Obj_GetPlayerObject();
    if (player == 0) {
        return;
    }

    if (obj->introDelay != 0) {
        obj->introDelay--;
        if (obj->introDelay == 0) {
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

    switch (runtime->state) {
    case DBSH_SHRINE_STATE_WAITING:
        obj->flags &= ~DBSH_SHRINE_OBJ_FLAG_ACTIVE;
        runtime->idleSfxTimer -= timeDelta;
        if (runtime->idleSfxTimer <= lbl_803E50DC) {
            Sfx_PlayFromObject(obj, DBSH_SHRINE_IDLE_SFX);
            rand = randomGetRange(500, 1000);
            randAsDouble.bits = CONCAT44(0x43300000, rand ^ 0x80000000);
            runtime->idleSfxTimer = (f32)(randAsDouble.value - lbl_803E50D0);
        }
        if ((obj->mapFlags & DBSH_SHRINE_MAP_FLAG_TRIGGERED) != 0) {
            active = MAP_EVENT_GET_ANIM(obj->mapId, 1);
            if (active != 0) {
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
        if ((runtime->flags & DBSH_SHRINE_LATCH_STARTED) != 0) {
            runtime->state = DBSH_SHRINE_STATE_ACTIVE;
            GameBit_Set(DBSH_SHRINE_GB_RISE_DONE, 1);
        }
        break;
    case DBSH_SHRINE_STATE_ACTIVE:
        if (GameBit_Get(DBSH_SHRINE_GB_CLOSE_A) != 0) {
            runtime->state = DBSH_SHRINE_STATE_CLOSING;
            runtime->resetTimer = 0;
        } else if (GameBit_Get(DBSH_SHRINE_GB_CLOSE_B) != 0) {
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
        runtime->flags &= ~DBSH_SHRINE_LATCH_STARTED;
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
