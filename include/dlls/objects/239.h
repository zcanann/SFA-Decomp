#ifndef DLLS_OBJECTS_239_H_
#define DLLS_OBJECTS_239_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/vec_types.h"

struct ObjSeqState;

typedef struct PushableMoveFlags {
    u8 activelyPushed : 1;
    u8 pushPromptEnabled : 1;
    u8 reserved : 6;
} PushableMoveFlags;

typedef struct PushableState {
    u8 pad00[0x0C];                /* 0x000 */
    f32 cullDistance;              /* 0x00C */
    f32 scale;                     /* 0x010 */
    f32 renderTimer;               /* 0x014 */
    Vec3f probeLocal[4];           /* 0x018 */
    Vec3f cornerLocal[4];          /* 0x048 */
    Vec3f cornerWorld[4];          /* 0x078 */
    u32 modelFlags;                /* 0x0A8: bits set by pushable_setModelFlag */
    s16 gameBit;                   /* 0x0AC */
    s16 gameBit2;                  /* 0x0AE */
    s32 unkB0;                     /* 0x0B0 */
    s8 pointCount;                 /* 0x0B4 */
    u8 padB5[3];                   /* 0x0B5 */
    GameObject* msgSenderObj;      /* 0x0B8 */
    GameObject* nearestObj;        /* 0x0BC */
    f32 knockbackVelX;             /* 0x0C0 */
    f32 knockbackVelY;             /* 0x0C4 */
    f32 knockbackVelZ;             /* 0x0C8 */
    f32 eyeOpenSpeed;              /* 0x0CC */
    f32 eyeDriftSpeedX;            /* 0x0D0 */
    f32 eyeDriftSpeedY;            /* 0x0D4 */
    f32 eyeOpenAmount;             /* 0x0D8 */
    f32 eyePosX;                   /* 0x0DC */
    f32 eyePosY;                   /* 0x0E0 */
    f32 blinkInterval;             /* 0x0E4 */
    f32 blinkStep;                 /* 0x0E8 */
    f32 blinkPhase;                /* 0x0EC */
    f32 magicGemDistanceThreshold; /* 0x0F0: set by message 0x40001 */
    f32 waterDepth;                /* 0x0F4 */
    f32 prevWaterDepth;            /* 0x0F8 */
    u8 padFC[4];                   /* 0x0FC */
    u16 flags;                     /* 0x100 */
    u8 cornerIdxPosZ;              /* 0x102 */
    u8 cornerIdxNegZ;              /* 0x103 */
    u8 cornerIdxPosX;              /* 0x104 */
    u8 cornerIdxNegX;              /* 0x105 */
    u8 pad106[2];                  /* 0x106 */
    f32 pushAmountX;               /* 0x108 */
    f32 pushAmountZ;               /* 0x10C */
    f32 airborneTimer;             /* 0x110 */
    PushableMoveFlags moveFlags;   /* 0x114 */
    s8 pushSfxTimer;               /* 0x115 */
    u8 pad116[2];                  /* 0x116 */
    f32 posHistX[5];               /* 0x118 */
    f32 posHistZ[5];               /* 0x12C */
    s32 yaw;                       /* 0x140 */
    u8 requiredHitId;              /* 0x144 */
    u8 savePosDelay;               /* 0x145 */
    u8 savePosEnabled;             /* 0x146 */
    u8 pad147;                     /* 0x147 */
} PushableState;

typedef int (*PushablePushCallback)(GameObject* obj, GameObject* target, int active, f32 pushX, f32 pushZ);
typedef int (*PushableIsWithinCullDistanceCallback)(GameObject* obj, GameObject* other);
typedef void (*PushableSetModelFlagCallback)(GameObject* obj, int modelNo);
typedef int (*PushableIsRestoredCallback)(GameObject* obj);

/* Complete runtime interface beginning at gPushableObjDescriptor's slot02. */
typedef struct PushableInterface {
    ObjectInterface base;
    PushablePushCallback push;
    PushableIsWithinCullDistanceCallback isWithinCullDistance;
    PushableSetModelFlagCallback setModelFlag;
    PushableIsRestoredCallback isRestored;
} PushableInterface;

typedef struct PushableDescriptor {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectInterfaceCallback slot02;
    ObjectInterfaceCallback init;
    ObjectInterfaceCallback update;
    ObjectInterfaceCallback hitDetect;
    ObjectInterfaceCallback render;
    ObjectInterfaceCallback free;
    ObjectInterfaceCallback getObjectTypeId;
    ObjectInterfaceExtraSizeCallback getExtraSize;
    PushablePushCallback push;
    PushableIsWithinCullDistanceCallback isWithinCullDistance;
    PushableSetModelFlagCallback setModelFlag;
    PushableIsRestoredCallback isRestored;
} PushableDescriptor;

#define PUSHABLE_INTERFACE(pushable) ((PushableInterface*)*((GameObject*)(pushable))->anim.dll)

typedef struct PushableObjectDef {
    ObjPlacement base; /* 0x00 */
    s16 gameBit;       /* 0x18 */
    s16 gameBit2;      /* 0x1A */
    s32 unk1C;         /* 0x1C */
    u16 scaleRaw;      /* 0x20 */
    u8 rotXByte;       /* 0x22 */
    s8 requiredHitId;  /* 0x23: triggering hit-region ID; -1 = none */
    u8 pad24[4];       /* 0x24 */
} PushableObjectDef;

typedef struct PushableRadii {
    f32 values[4];
} PushableRadii;

STATIC_ASSERT(sizeof(PushableMoveFlags) == 0x1);

STATIC_ASSERT(offsetof(PushableState, pad00) == 0x0);
STATIC_ASSERT(offsetof(PushableState, cullDistance) == 0xC);
STATIC_ASSERT(offsetof(PushableState, scale) == 0x10);
STATIC_ASSERT(offsetof(PushableState, renderTimer) == 0x14);
STATIC_ASSERT(offsetof(PushableState, probeLocal) == 0x18);
STATIC_ASSERT(offsetof(PushableState, cornerLocal) == 0x48);
STATIC_ASSERT(offsetof(PushableState, cornerWorld) == 0x78);
STATIC_ASSERT(offsetof(PushableState, modelFlags) == 0xA8);
STATIC_ASSERT(offsetof(PushableState, gameBit) == 0xAC);
STATIC_ASSERT(offsetof(PushableState, gameBit2) == 0xAE);
STATIC_ASSERT(offsetof(PushableState, unkB0) == 0xB0);
STATIC_ASSERT(offsetof(PushableState, pointCount) == 0xB4);
STATIC_ASSERT(offsetof(PushableState, padB5) == 0xB5);
STATIC_ASSERT(offsetof(PushableState, msgSenderObj) == 0xB8);
STATIC_ASSERT(offsetof(PushableState, nearestObj) == 0xBC);
STATIC_ASSERT(offsetof(PushableState, knockbackVelX) == 0xC0);
STATIC_ASSERT(offsetof(PushableState, knockbackVelY) == 0xC4);
STATIC_ASSERT(offsetof(PushableState, knockbackVelZ) == 0xC8);
STATIC_ASSERT(offsetof(PushableState, eyeOpenSpeed) == 0xCC);
STATIC_ASSERT(offsetof(PushableState, eyeDriftSpeedX) == 0xD0);
STATIC_ASSERT(offsetof(PushableState, eyeDriftSpeedY) == 0xD4);
STATIC_ASSERT(offsetof(PushableState, eyeOpenAmount) == 0xD8);
STATIC_ASSERT(offsetof(PushableState, eyePosX) == 0xDC);
STATIC_ASSERT(offsetof(PushableState, eyePosY) == 0xE0);
STATIC_ASSERT(offsetof(PushableState, blinkInterval) == 0xE4);
STATIC_ASSERT(offsetof(PushableState, blinkStep) == 0xE8);
STATIC_ASSERT(offsetof(PushableState, blinkPhase) == 0xEC);
STATIC_ASSERT(offsetof(PushableState, magicGemDistanceThreshold) == 0xF0);
STATIC_ASSERT(offsetof(PushableState, waterDepth) == 0xF4);
STATIC_ASSERT(offsetof(PushableState, prevWaterDepth) == 0xF8);
STATIC_ASSERT(offsetof(PushableState, padFC) == 0xFC);
STATIC_ASSERT(offsetof(PushableState, flags) == 0x100);
STATIC_ASSERT(offsetof(PushableState, cornerIdxPosZ) == 0x102);
STATIC_ASSERT(offsetof(PushableState, cornerIdxNegZ) == 0x103);
STATIC_ASSERT(offsetof(PushableState, cornerIdxPosX) == 0x104);
STATIC_ASSERT(offsetof(PushableState, cornerIdxNegX) == 0x105);
STATIC_ASSERT(offsetof(PushableState, pad106) == 0x106);
STATIC_ASSERT(offsetof(PushableState, pushAmountX) == 0x108);
STATIC_ASSERT(offsetof(PushableState, pushAmountZ) == 0x10C);
STATIC_ASSERT(offsetof(PushableState, airborneTimer) == 0x110);
STATIC_ASSERT(offsetof(PushableState, moveFlags) == 0x114);
STATIC_ASSERT(offsetof(PushableState, pushSfxTimer) == 0x115);
STATIC_ASSERT(offsetof(PushableState, pad116) == 0x116);
STATIC_ASSERT(offsetof(PushableState, posHistX) == 0x118);
STATIC_ASSERT(offsetof(PushableState, posHistZ) == 0x12C);
STATIC_ASSERT(offsetof(PushableState, yaw) == 0x140);
STATIC_ASSERT(offsetof(PushableState, requiredHitId) == 0x144);
STATIC_ASSERT(offsetof(PushableState, savePosDelay) == 0x145);
STATIC_ASSERT(offsetof(PushableState, savePosEnabled) == 0x146);
STATIC_ASSERT(offsetof(PushableState, pad147) == 0x147);
STATIC_ASSERT(sizeof(PushableState) == 0x148);

STATIC_ASSERT(offsetof(PushableInterface, base) == 0x00);
STATIC_ASSERT(offsetof(PushableInterface, push) == 0x20);
STATIC_ASSERT(offsetof(PushableInterface, isWithinCullDistance) == 0x24);
STATIC_ASSERT(offsetof(PushableInterface, setModelFlag) == 0x28);
STATIC_ASSERT(offsetof(PushableInterface, isRestored) == 0x2C);
STATIC_ASSERT(sizeof(PushableInterface) == 0x30);

STATIC_ASSERT(offsetof(PushableDescriptor, reserved0) == 0x00);
STATIC_ASSERT(offsetof(PushableDescriptor, slotCountAndFlags) == 0x0C);
STATIC_ASSERT(offsetof(PushableDescriptor, initialise) == 0x10);
STATIC_ASSERT(offsetof(PushableDescriptor, release) == 0x14);
STATIC_ASSERT(offsetof(PushableDescriptor, slot02) == 0x18);
STATIC_ASSERT(offsetof(PushableDescriptor, getExtraSize) == 0x34);
STATIC_ASSERT(offsetof(PushableDescriptor, push) == 0x38);
STATIC_ASSERT(offsetof(PushableDescriptor, isWithinCullDistance) == 0x3C);
STATIC_ASSERT(offsetof(PushableDescriptor, setModelFlag) == 0x40);
STATIC_ASSERT(offsetof(PushableDescriptor, isRestored) == 0x44);
STATIC_ASSERT(sizeof(PushableDescriptor) == 0x48);

STATIC_ASSERT(offsetof(PushableObjectDef, base) == 0x0);
STATIC_ASSERT(offsetof(PushableObjectDef, gameBit) == 0x18);
STATIC_ASSERT(offsetof(PushableObjectDef, gameBit2) == 0x1A);
STATIC_ASSERT(offsetof(PushableObjectDef, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(PushableObjectDef, scaleRaw) == 0x20);
STATIC_ASSERT(offsetof(PushableObjectDef, rotXByte) == 0x22);
STATIC_ASSERT(offsetof(PushableObjectDef, requiredHitId) == 0x23);
STATIC_ASSERT(offsetof(PushableObjectDef, pad24) == 0x24);
STATIC_ASSERT(sizeof(PushableObjectDef) == 0x28);

STATIC_ASSERT(offsetof(PushableRadii, values) == 0x0);
STATIC_ASSERT(sizeof(PushableRadii) == 0x10);

int pushable_updateCurtain(GameObject* obj, PushableState* state);
void pushable_initWcPushBlock(GameObject* obj, PushableState* state);
int pushable_updateMagicGem(GameObject* obj, PushableState* state);
void pushable_initMagicGem(GameObject* obj, PushableState* state);
void pushable_resolveCollisions(GameObject* obj, PushableState* state);
u32 pushable_SeqFn(GameObject* obj, struct MatrixTransform* referenceTransform, struct ObjSeqState* animUpdate);
void pushable_handleMsgs(GameObject* obj, int unused);
int pushable_isRestored(GameObject* obj);
void pushable_setModelFlag(GameObject* obj, int modelNo);
int pushable_isWithinCullDistance(GameObject* obj, GameObject* other);
int pushable_push(GameObject* obj, GameObject* target, int active, f32 pushX, f32 pushZ);
int pushable_getExtraSize(void);
int pushable_getObjectTypeId(void);
void pushable_free(GameObject* obj);
void pushable_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void pushable_hitDetect(GameObject* obj);
void pushable_update(GameObject* obj);
void pushable_init(GameObject* obj, PushableObjectDef* setup);

extern int gPushableSavedIdentCount;
extern int gPushableSavedIdents[0x28];
extern char sPushPullObjectHitpointOverflow[];
extern const PushableRadii gPushableDefaultBox;
extern PushableDescriptor gPushableObjDescriptor;

#endif /* DLLS_OBJECTS_239_H_ */
