#ifndef DLLS_OBJECTS_208_GRIMBLE_H_
#define DLLS_OBJECTS_208_GRIMBLE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/baddie_state.h"

typedef struct GrimblePathObject GrimblePathObject;

typedef struct GrimblePathCallbacks {
    u8 pad00[0x20];
    void (*initialise)(GrimblePathObject* pathObj, void* pathState);
    void (*sample)(GrimblePathObject* pathObj, f32 progress, f32* x, f32* y, f32* z);
    void (*advance)(GrimblePathObject* pathObj, f32* progress, f32 delta);
    u8 pad2C[0x30 - 0x2C];
    int (*findNearest)(GrimblePathObject* pathObj, f32 x, f32 y, f32 z, f32* distance, f32* progress, f32* aux);
    s16 (*getRotation)(GrimblePathObject* pathObj);
} GrimblePathCallbacks;

typedef struct GrimblePathInterface {
    GrimblePathCallbacks* callbacks;
} GrimblePathInterface;

struct GrimblePathObject {
    u8 pad00[0x68];
    GrimblePathInterface* pathInterface;
};

STATIC_ASSERT(offsetof(GrimblePathCallbacks, initialise) == 0x20);
STATIC_ASSERT(offsetof(GrimblePathCallbacks, sample) == 0x24);
STATIC_ASSERT(offsetof(GrimblePathCallbacks, advance) == 0x28);
STATIC_ASSERT(offsetof(GrimblePathCallbacks, findNearest) == 0x30);
STATIC_ASSERT(offsetof(GrimblePathCallbacks, getRotation) == 0x34);
STATIC_ASSERT(offsetof(GrimblePathInterface, callbacks) == 0x0);
STATIC_ASSERT(offsetof(GrimblePathObject, pathInterface) == 0x68);

/*
 * Per-family control record addressed by GroundBaddieState.control. It follows
 * the shared GroundBaddieState prefix in Grimble's object-extra allocation.
 */
typedef struct GrimbleControl {
    f32 posYDelta;                       /* 0x00 */
    f32 anchorPosY;                      /* 0x04 */
    f32 currentPosY;                     /* 0x08 */
    u8 pathState[0x1C - 0xC];            /* 0x0C: opaque state owned by the path object */
    f32 pathPosX;                        /* 0x1C */
    f32 pathPosY;                        /* 0x20 */
    f32 pathPosZ;                        /* 0x24 */
    u8 pad28[0x34 - 0x28];               /* 0x28 */
    GrimblePathObject* candidatePathObj; /* 0x34 */
    GrimblePathObject* pathObj;          /* 0x38 */
    f32 nearestDist;                     /* 0x3C */
    f32 candidateProgress;               /* 0x40 */
    u8 unk44;                            /* 0x44 */
    s8 reversed;                         /* 0x45 */
    u8 unk46;                            /* 0x46 */
    u8 pad47;                            /* 0x47 */
    f32 pathProgress;                    /* 0x48 */
    f32 savedPathProgress;               /* 0x4C */
    f32 unk50;                           /* 0x50 */
    f32 targetProgress;                  /* 0x54 */
    s16 baseRotX;                        /* 0x58 */
    u8 pad5A[2];                         /* 0x5A */
} GrimbleControl;

STATIC_ASSERT(offsetof(GrimbleControl, posYDelta) == 0x0);
STATIC_ASSERT(offsetof(GrimbleControl, anchorPosY) == 0x4);
STATIC_ASSERT(offsetof(GrimbleControl, currentPosY) == 0x8);
STATIC_ASSERT(offsetof(GrimbleControl, pathState) == 0xC);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosX) == 0x1C);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosY) == 0x20);
STATIC_ASSERT(offsetof(GrimbleControl, pathPosZ) == 0x24);
STATIC_ASSERT(offsetof(GrimbleControl, candidatePathObj) == 0x34);
STATIC_ASSERT(offsetof(GrimbleControl, pathObj) == 0x38);
STATIC_ASSERT(offsetof(GrimbleControl, nearestDist) == 0x3C);
STATIC_ASSERT(offsetof(GrimbleControl, candidateProgress) == 0x40);
STATIC_ASSERT(offsetof(GrimbleControl, reversed) == 0x45);
STATIC_ASSERT(offsetof(GrimbleControl, pathProgress) == 0x48);
STATIC_ASSERT(offsetof(GrimbleControl, savedPathProgress) == 0x4C);
STATIC_ASSERT(offsetof(GrimbleControl, unk50) == 0x50);
STATIC_ASSERT(offsetof(GrimbleControl, targetProgress) == 0x54);
STATIC_ASSERT(offsetof(GrimbleControl, baseRotX) == 0x58);
STATIC_ASSERT(sizeof(GrimbleControl) == 0x5C);

int grimble_stateHandlerB05(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerB04(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerB03(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerB02(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerB01(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerB00(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA09(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA08(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA07(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA06(GameObject* obj, GroundBaddieState* state, f32 speed);
int grimble_stateHandlerA05(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA04(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA03(GameObject* obj, GroundBaddieState* state);
int grimble_stateHandlerA02(GameObject* obj, char* state, f32 timeDelta);
int grimble_stateHandlerA01(GameObject* obj, char* state, f32 timeDelta);
int grimble_stateHandlerA00(GameObject* obj, char* state, f32 timeDelta);
int grimble_animEventCallback(void);
void grimble_attachNearestPath(GameObject* obj);

int grimble_getExtraSize(void);
int grimble_getObjectTypeId(void);
void grimble_free(GameObject* obj);
void grimble_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void grimble_hitDetect(GameObject* obj);
void grimble_update(GameObject* obj);
void grimble_init(GameObject* obj, ObjPlacement* placement, int flags);
void grimble_release(void);
void grimble_initialise(void);
void grimble_initialiseStateHandlerTables(void);

extern void* gGrimbleStateHandlersB[6];
extern void* gGrimbleStateHandlersA[10];
extern int gGrimbleHitReactionMoves[30];
extern u8 gGrimbleHitReactionDamage[32];
extern ObjectDescriptor gGrimbleObjDescriptor;

#endif /* DLLS_OBJECTS_208_GRIMBLE_H_ */
