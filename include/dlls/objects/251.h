#ifndef DLLS_OBJECTS_251_H_
#define DLLS_OBJECTS_251_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

typedef struct PressureSwitchFBPlacement {
    ObjPlacement base;  /* 0x00 */
    u8 rotXByte;        /* 0x18: X rotation in 1/256 turns */
    u8 modelBankIndex;  /* 0x19 */
    s16 pressedGameBit; /* 0x1A */
    u8 pressDepth;      /* 0x1C */
    u8 triggerHeight;   /* 0x1D */
    u8 drivesTricky;    /* 0x1E */
    u8 unk1F;           /* 0x1F */
    s16 enableGameBit;  /* 0x20: -1 = always enabled */
    u8 pad22[2];        /* 0x22 */
} PressureSwitchFBPlacement;

typedef struct PressureSwitchFBFlags {
    u8 active : 1;
    u8 playerOnly : 1;
    u8 released : 1;
    u8 latched : 1;
    u8 unused : 4;
} PressureSwitchFBFlags;

typedef struct PressureSwitchFBTrackedPosition {
    f32 x;
    f32 z;
} PressureSwitchFBTrackedPosition;

typedef struct PressureSwitchFBState {
    s8 contactTimer;                                      /* 0x00 */
    u8 pad01[3];                                          /* 0x01 */
    GameObject* trackedObjects[10];                       /* 0x04 */
    PressureSwitchFBTrackedPosition trackedPositions[10]; /* 0x2C */
    f32 targetPosY;                                       /* 0x7C */
    f32 velocityY;                                        /* 0x80 */
    PressureSwitchFBFlags flags;                          /* 0x84 */
    u8 pad85[3];                                          /* 0x85 */
} PressureSwitchFBState;

STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, modelBankIndex) == 0x19);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, pressedGameBit) == 0x1A);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, pressDepth) == 0x1C);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, triggerHeight) == 0x1D);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, drivesTricky) == 0x1E);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, unk1F) == 0x1F);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, enableGameBit) == 0x20);
STATIC_ASSERT(offsetof(PressureSwitchFBPlacement, pad22) == 0x22);
STATIC_ASSERT(sizeof(PressureSwitchFBPlacement) == 0x24);

STATIC_ASSERT(offsetof(PressureSwitchFBState, contactTimer) == 0x0);
STATIC_ASSERT(offsetof(PressureSwitchFBState, pad01) == 0x1);
STATIC_ASSERT(offsetof(PressureSwitchFBState, trackedObjects) == 0x4);
STATIC_ASSERT(offsetof(PressureSwitchFBState, trackedPositions) == 0x2C);
STATIC_ASSERT(offsetof(PressureSwitchFBState, targetPosY) == 0x7C);
STATIC_ASSERT(offsetof(PressureSwitchFBState, velocityY) == 0x80);
STATIC_ASSERT(offsetof(PressureSwitchFBState, flags) == 0x84);
STATIC_ASSERT(offsetof(PressureSwitchFBState, pad85) == 0x85);
STATIC_ASSERT(sizeof(PressureSwitchFBState) == 0x88);

int PressureSwitchFB_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
int PressureSwitchFB_getExtraSize(void);
void PressureSwitchFB_free(GameObject* obj);
void PressureSwitchFB_update(GameObject* obj);
void PressureSwitchFB_init(GameObject* obj, PressureSwitchFBPlacement* placement);

extern ObjectDescriptor gPressureSwitchFBObjDescriptor;

#endif /* DLLS_OBJECTS_251_H_ */
