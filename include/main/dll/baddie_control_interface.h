#ifndef MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_
#define MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ObjSeqState ObjSeqState;

/* Function-pointer table exported by the baddie-control DLL (0x19); slot K
 * here is the DLL's exported func(K - 4) (updateMovementBlend = dll_19_func06,
 * getTargetGeometry = dll_19_func07, getClearDirectionMask = dll_19_func08,
 * releaseState = dll_19_func12,
 * shouldDropTarget = dll_19_func13, findAggroTarget = dll_19_func14,
 * updateHitReaction = dll_19_func16, processMessages = dll_19_func17,
 * initGroundBaddie = dll_19_func18). Named slots are those with recovered call
 * sites; the pads are unrecovered slots. */
typedef struct BaddieControlInterface
{
    u8 pad00[0x10];
    void (*updateMovementBlend)(GameObject* obj, void* state, void* unusedState, f32 maxSpeed,
                                f32 turnSpeed); /* 0x10 */
    void (*getTargetGeometry)(GameObject* obj, GameObject* target, int divisions, u16* sectorOut,
                              u16* yawDeltaOut, u16* distanceOut); /* 0x14 */
    u8 (*getClearDirectionMask)(GameObject* obj, void* state, f32 distance); /* 0x18 */
    u8 pad1C[0x28 - 0x1C];
    void (*startHitReaction)(GameObject* obj, void* state, void* hitbox, s16 gameBit, u8* flagOut,
                             s16 substate, s16 moveMode, int animMove, s8 physicsActive); /* 0x28 */
    void (*updateGravity)(GameObject* obj, void* state, f32 gravity, s8 physicsActive); /* 0x2C */
    int (*isObjectValid)(GameObject* obj, void* state, u8 checkDead);        /* 0x30 */
    int (*updateSequenceMovement)(GameObject* obj, ObjSeqState* seq, char* state, void* moveHandlers,
                                  void* stateHandlers, s16 controlMode);     /* 0x34 */
    u8 pad38[0x40 - 0x38];
    void (*releaseState)(GameObject* obj, void* state, u8 flags);            /* 0x40 */
    int (*shouldDropTarget)(GameObject* obj, void* state, f32 distanceThreshold, int requireFar); /* 0x44 */
    GameObject* (*findAggroTarget)(GameObject* obj, void* state, f32 aggroRange, int angleRange); /* 0x48 */
    GameObject* (*spawnChild)(GameObject* obj, int spawnType, int unused, int alt); /* 0x4C */
    int (*updateHitReaction)(GameObject* obj, void* state, void* hitbox, s16 gameBit, int* moveTable,
                             u8* damageTable, s16 substate, void* hitPosOut); /* 0x50 */
    int (*processMessages)(GameObject* obj, void* state, void* hitbox, s16 gameBit, u8* flagOut,
                           s16 substateIdle, s16 substateActive, s16 moveMode); /* 0x54 */
    void (*initGroundBaddie)(GameObject* obj, u8* config, u8* state, int moveArg0, int moveArg1,
                             int pathFlags, u8 initFlags, f32 pathRadius); /* 0x58 */
} BaddieControlInterface;

extern int* gBaddieControlInterface;

#endif /* MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_ */
