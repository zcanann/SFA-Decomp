#ifndef DLLS_OBJECTS_294_H_
#define DLLS_OBJECTS_294_H_

#include "global.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

typedef struct MMPTriggerGeyserPlacement {
    ObjPlacement base;
    u8 unknown18[0x3A - 0x18];
    u8 reachScale;
    u8 speed;
    u8 unknown3C;
    u8 rotX;
    u8 rotY;
} MMPTriggerGeyserPlacement;

STATIC_ASSERT(offsetof(MMPTriggerGeyserPlacement, reachScale) == 0x3A);
STATIC_ASSERT(offsetof(MMPTriggerGeyserPlacement, speed) == 0x3B);
STATIC_ASSERT(offsetof(MMPTriggerGeyserPlacement, rotX) == 0x3D);
STATIC_ASSERT(offsetof(MMPTriggerGeyserPlacement, rotY) == 0x3E);

typedef struct MmpGyserventState {
    u8 pad0[0x4 - 0x0];
    f32 nearRadiusSq; /* 0x04: squared near-distance threshold */
    u8 pad8[0xC - 0x8];
    f32 planeNormalX; /* 0x0C: clip-plane normal (vent local forward) */
    f32 planeNormalY; /* 0x10 */
    f32 planeNormalZ; /* 0x14 */
    f32 planeOffset;  /* 0x18: plane d term */
    f32 reachAX;      /* 0x1C: reach endpoint A */
    f32 reachAY;      /* 0x20 */
    f32 reachAZ;      /* 0x24 */
    f32 reachBX;      /* 0x28: reach endpoint B */
    f32 reachBY;      /* 0x2C */
    f32 reachBZ;      /* 0x30 */
    f32 reach;        /* 0x34: eruption reach distance */
    f32 mtx[3][4];    /* 0x38: world->vent-local transform */
} MmpGyserventState;

STATIC_ASSERT(offsetof(MmpGyserventState, nearRadiusSq) == 0x04);
STATIC_ASSERT(offsetof(MmpGyserventState, planeNormalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpGyserventState, planeOffset) == 0x18);
STATIC_ASSERT(offsetof(MmpGyserventState, reachAX) == 0x1C);
STATIC_ASSERT(offsetof(MmpGyserventState, reachBX) == 0x28);
STATIC_ASSERT(offsetof(MmpGyserventState, reach) == 0x34);
STATIC_ASSERT(offsetof(MmpGyserventState, mtx) == 0x38);

/* flag byte at TriggerState + 0x8A; bit7 = the 0x54 once-only latch */
typedef struct {
    u8 bit7 : 1;
    u8 lo : 7;
} TriggerFlags8A;

typedef struct TriggerCommand {
    u8 condition;
    u8 id;
    u8 param1;
    u8 param2;
} TriggerCommand;

typedef struct TriggerPlacement {
    ObjPlacement base;
    TriggerCommand commands[8];
    s16 triggerId; /* 0x38: id matched against dispatched trigger message id */
    u8 size[3];    /* 0x3A: dimensions (x,y,z) */
    u8 rot[2];     /* 0x3D: rotation (x,y), range 0-255 */
    u8 pad3F[0x43 - 0x3F];
    u8 target;              /* 0x43: object the trigger applies to / can be activated by */
    s16 gameBitSrc;         /* 0x44: game-bit id copied into TriggerState.gameBit */
    u16 triggerDelayFrames; /* 0x46: frames the timer must reach before firing */
    s16 gateBitSrc[4];      /* 0x48/0x4a/0x4c/0x4e: game-bit ids copied into TriggerState.gateBits */
} TriggerPlacement;

typedef struct ObjInterpretSeqPlacement {
    u8 pad0[0x2 - 0x0];
    s8 commandVariant; /* 0x2: sub-selector dispatched per interpret-seq opcode */
    u8 pad3[0x4 - 0x3];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} ObjInterpretSeqPlacement;

typedef struct TriggerState {
    u8 status;
    u8 pad1[0x4 - 0x1];
    f32 rangeSq;
    u32 timer;
    u8 padC[0x1C - 0xC];
    f32 targetPosX;
    f32 targetPosY;
    f32 targetPosZ;
    f32 prevTargetPosX;
    f32 prevTargetPosY;
    f32 prevTargetPosZ;
    u8 pad34[0x80 - 0x34];
    s16 gameBit;
    s16 gateBits[4];
    TriggerFlags8A flags8A;
    u8 pad8B[0xAC - 0x8B];
} TriggerState;

STATIC_ASSERT(offsetof(TriggerState, flags8A) == 0x8A);
STATIC_ASSERT(sizeof(TriggerCommand) == 4);
STATIC_ASSERT(offsetof(TriggerPlacement, base.objectId) == 0x0);
STATIC_ASSERT(offsetof(TriggerPlacement, commands) == 0x18);
STATIC_ASSERT(offsetof(TriggerPlacement, triggerId) == 0x38);
STATIC_ASSERT(offsetof(TriggerPlacement, size) == 0x3A);
STATIC_ASSERT(offsetof(TriggerPlacement, rot) == 0x3D);
STATIC_ASSERT(offsetof(TriggerPlacement, target) == 0x43);
STATIC_ASSERT(offsetof(TriggerPlacement, gameBitSrc) == 0x44);
STATIC_ASSERT(offsetof(TriggerPlacement, triggerDelayFrames) == 0x46);
STATIC_ASSERT(offsetof(TriggerPlacement, gateBitSrc) == 0x48);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, commandVariant) == 0x2);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, unk4) == 0x4);
STATIC_ASSERT(offsetof(ObjInterpretSeqPlacement, unk6) == 0x6);
STATIC_ASSERT(offsetof(TriggerState, rangeSq) == 0x4);
STATIC_ASSERT(offsetof(TriggerState, status) == 0x0);
STATIC_ASSERT(offsetof(TriggerState, timer) == 0x8);
STATIC_ASSERT(offsetof(TriggerState, targetPosX) == 0x1C);
STATIC_ASSERT(offsetof(TriggerState, gameBit) == 0x80);
STATIC_ASSERT(offsetof(TriggerState, gateBits) == 0x82);
STATIC_ASSERT(sizeof(TriggerState) == 0xAC);

typedef struct MmpTriggerPlaneState {
    u8 header[0xC];     /* 0x00 */
    f32 normalX;        /* 0x0C plane normal */
    f32 normalY;        /* 0x10 */
    f32 normalZ;        /* 0x14 */
    f32 planeD;         /* 0x18 plane constant */
    f32 ptA[3];         /* 0x1C near segment endpoint */
    f32 ptB[3];         /* 0x28 far segment endpoint */
    f32 clipHalfExtent; /* 0x34 trigger-local half size */
    f32 mtx[3][4];      /* 0x38 world->trigger-local transform */
} MmpTriggerPlaneState;

STATIC_ASSERT(offsetof(MmpTriggerPlaneState, normalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, planeD) == 0x18);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptA) == 0x1C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptB) == 0x28);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, clipHalfExtent) == 0x34);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, mtx) == 0x38);

extern ObjectDescriptor gTriggerObjDescriptor;
extern char sMoonrockTriggerIdentFormat[];
extern char sTriggerDebugTextBlock[];

void objInterpretSeq(GameObject* obj, GameObject* seqObj, s8 legCode, int range);
void Trigger_render(void);
void Trigger_update(void);
void Trigger_release(void);
void Trigger_initialise(void);
void Trigger_free(GameObject* obj);
void Trigger_init(GameObject* obj, u8* params);
int Trigger_getExtraSize(void);
int Trigger_getObjectTypeId(void);
void Trigger_hitDetect(GameObject* obj);

void MmpGyservent_setup(GameObject* obj, MMPTriggerGeyserPlacement* placement);
void triggerEvalEndpointCylinders(GameObject* obj, GameObject* seqObj);
void triggerEvalEndpointSpheres(GameObject* obj, GameObject* seqObj);

#endif /* DLLS_OBJECTS_294_H_ */
