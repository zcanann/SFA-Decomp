#ifndef DLLS_OBJECTS_578_DBSTEALERWO_H_
#define DLLS_OBJECTS_578_DBSTEALERWO_H_

#include "game/objects/object.h"
#include "main/dll/baddie_state.h"
#include "main/model_engine.h"

/* gDBstealerwormObjDescriptor from slot02 onwards: the export table sibling
   worms reach through obj->anim.dll. */
typedef struct DbStealerwormInterface {
    void* pad00[8];
    int (*getControlMode)(struct GameObject* worm);
    int (*handleMessage)(struct GameObject* worm, u8 msg, int* out);
} DbStealerwormInterface;

#define DB_STEALERWORM_INTERFACE(worm) ((DbStealerwormInterface*)*((struct GameObject*)(worm))->anim.dll)

STATIC_ASSERT(offsetof(DbStealerwormInterface, getControlMode) == 0x20);
STATIC_ASSERT(offsetof(DbStealerwormInterface, handleMessage) == 0x24);

typedef struct DbStealerwormMessageFrame {
    int code;
    int mode;
    int objGroup;
} DbStealerwormMessageFrame;

typedef DbStealerwormMessageFrame DbStealerwormScriptStep;

typedef struct DbStealerwormScript {
    const DbStealerwormScriptStep* steps;
    s16 stepCount;
    s16 unk6;
} DbStealerwormScript;

typedef struct DbStealerwormFlags44 {
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
    u8 low : 4;
} DbStealerwormFlags44;

typedef struct DbStealerwormControl {
    const DbStealerwormScript* script;
    f32 unk04;
    f32 unk08;
    f32 countdown;   /* countdown; init randomGetRange(10, 300) */
    f32 nextSfxTime; /* countdown threshold; on cross plays sfx, advances by randomGetRange(50,250) */
    u8 flags14;      /* bits 1/2 */
    u8 flags15;      /* bits 1/4 */
    u8 unk16[2];
    union {
        int linkedObj;
        struct GameObject* linkedObject; /* ObjMsg target object */
    };
    s16 heldScriptSlot; /* queued message-config slot index (-1 = none); pushed as the type-7 frame payload */
    u8 unk1E[2];
    const DbStealerwormScriptStep* scriptCursor;
    RingBufferQueue* messageStack; /* queued 3-word messages */
    int messageCode;               /* current message word 0: code dispatched to the player interface (frame[0]) */
    int messageMode;               /* current message word 1: target-acquisition mode 0/1 (frame[1]) */
    int messageObjGroup;           /* current message word 2: ObjGroup id for FindNearest/Contains (frame[2]) */
    u8 advanceMessage;             /* set to advance to / pop the next queued message next tick */
    u8 unk35[3];
    f32 spawnAccumulator; /* 0x38: accumulates on worm move-done; when over threshold, triggers a spawn-search and subtracts the threshold */
    union {
        int savedTargetObj; /* cached target-object handle */
        struct GameObject* savedTargetObject;
    };
    u8 unk40[4];
    DbStealerwormFlags44 flags44;
    u8 unk45[3];
    f32 randomTimer48; /* RandomTimer_UpdateRangeTrigger slots */
    f32 randomTimer4C;
} DbStealerwormControl;

typedef struct {
    int* msgs; /* 0x00 */
    s16 count; /* 0x04 */
    u8 pad06[0x08 - 0x06];
} DbWormMsgGroup;
typedef struct DbWormEffectSpawnWork {
    s16 rotX; /* 0x00 */
    s16 rotY;
    s16 rotZ;
    u8 pad6[2];
    f32 scale; /* 0x08 */
    f32 posX;  /* 0x0C: fx spawn position */
    f32 posY;
    f32 posZ;
} DbWormEffectSpawnWork;
typedef struct DbStealerwormObjDescriptorLayout {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    void (*callbacks[12])(void);
    char debugStrings[0x5C];
} DbStealerwormObjDescriptorLayout;

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);
STATIC_ASSERT(sizeof(DbWormMsgGroup) == 0x08);
STATIC_ASSERT(sizeof(DbWormEffectSpawnWork) == 0x18);
STATIC_ASSERT(offsetof(DbStealerwormObjDescriptorLayout, callbacks) == 0x10);
STATIC_ASSERT(offsetof(DbStealerwormObjDescriptorLayout, debugStrings) == 0x40);
STATIC_ASSERT(sizeof(DbStealerwormObjDescriptorLayout) == 0x9C);

extern void* gDBStealerWormStateHandlersA[];
extern void* gDBStealerWormStateHandlersB[];

int dbstealerworm_stateHandlerA00(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA01(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA02(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA03(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA04(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA05(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA06(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA07(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA08(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA09(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0A(GameObject* obj, BaddieState* state);
int dbstealerworm_stateHandlerA0B(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA0C(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerA0D(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0E(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerA0F(GameObject* obj, BaddieState* baddie, f32 t);
int dbstealerworm_stateHandlerB00(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB01(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB02(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB03(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB04(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB05(GameObject* obj, BaddieState* baddie);
int dbstealerworm_stateHandlerB06(GameObject* obj, BaddieState* baddie);
void dbstealerworm_launchIceBall(GameObject* obj, BaddieState* baddie);

int dbstealerworm_getControlMode(GameObject* obj);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_getObjectTypeId(void);
void dbstealerworm_free(GameObject* obj);
void dbstealerworm_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dbstealerworm_hitDetect(GameObject* obj);
void dbstealerworm_update(GameObject* obj);
void dbstealerworm_init(GameObject* obj, u8* def, int flag);
void dbstealerworm_release(void);
void dbstealerworm_initialise(void);
void DBstealerwo_setFuncPtrs(void);

int dbstealerworm_handleMessage(GameObject* obj, u8 msg, int* out);

extern int gDbStealerwormRunToAvoidGroups[];
extern f32 gDbStealerwormRunToAvoidWeights[];
extern int gDbStealerwormWaitAvoidGroups[];
extern f32 gDbStealerwormWaitAvoidWeights[];
extern int gDbStealerwormKillAvoidGroups[];
extern f32 gDbStealerwormKillAvoidWeights[];
extern DbStealerwormScript gDbStealerwormScriptTable[];
extern int gDbStealerwormDeathFootstepSfx[];
extern int gDbStealerwormBurrowFootstepSfx[];
extern int gDbStealerwormSfxIds[];
extern DbStealerwormScriptStep gDbStealerwormScriptStealEggThrowToWorm[];

extern DbStealerwormObjDescriptorLayout gDBstealerwormObjDescriptor;

#endif /* DLLS_OBJECTS_578_DBSTEALERWO_H_ */
