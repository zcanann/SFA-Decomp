#ifndef MAIN_DLL_DLL_0126_TRIGGER_H_
#define MAIN_DLL_DLL_0126_TRIGGER_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct TriggerPlacement
{
    s16 typeId; /* 0x0: object-sequence type id dispatched by Trigger_init */
    u8 pad2[0x38 - 0x2];
    s16 triggerId; /* 0x38: id matched against dispatched trigger message id */
    u8 size[3];    /* 0x3A: dimensions (x,y,z) */
    u8 rot[2];     /* 0x3D: rotation (x,y), range 0-255 */
    u8 pad3F[0x43 - 0x3F];
    u8 target;              /* 0x43: object the trigger applies to / can be activated by */
    s16 gameBitSrc;         /* 0x44: game-bit id copied into TriggerState.gameBit */
    u16 triggerDelayFrames; /* 0x46: frames the timer must reach before firing */
    s16 gateBitSrc[4];      /* 0x48/0x4a/0x4c/0x4e: game-bit ids copied into TriggerState.gateBits */
} TriggerPlacement;

typedef struct ObjInterpretSeqPlacement
{
    u8 pad0[0x2 - 0x0];
    s8 commandVariant; /* 0x2: sub-selector dispatched per interpret-seq opcode */
    u8 pad3[0x4 - 0x3];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} ObjInterpretSeqPlacement;

typedef struct TriggerState
{
    u8 pad0[0x4 - 0x0];
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
    u8 pad8A[0xAC - 0x8A];
} TriggerState;

/* flag byte at TriggerState + 0x8A; bit7 = the 0x54 once-only latch */
typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} TriggerFlags8A;

STATIC_ASSERT(offsetof(TriggerPlacement, typeId) == 0x0);
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
STATIC_ASSERT(offsetof(TriggerState, timer) == 0x8);
STATIC_ASSERT(offsetof(TriggerState, targetPosX) == 0x1C);
STATIC_ASSERT(offsetof(TriggerState, gameBit) == 0x80);
STATIC_ASSERT(offsetof(TriggerState, gateBits) == 0x82);
STATIC_ASSERT(sizeof(TriggerState) == 0xAC);

extern ObjectDescriptor gTriggerObjDescriptor;

void Trigger_render(void);
void Trigger_update(void);
void Trigger_release(void);
void Trigger_initialise(void);
void Trigger_free(GameObject* obj);
void Trigger_init(u8* obj, u8* params);
int Trigger_getExtraSize(void);
int Trigger_getObjectTypeId(void);
void objInterpretSeq(int obj, int seqArg, int legCode, int distSq);
void Trigger_hitDetect(GameObject* obj);

#endif /* MAIN_DLL_DLL_0126_TRIGGER_H_ */
