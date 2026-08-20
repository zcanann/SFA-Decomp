#ifndef DLLS_OBJECTS_437_H_
#define DLLS_OBJECTS_437_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/baddie_state.h"

#define DLL1B5_STATE_HANDLER_COUNT                   5
#define DLL1B5_SUBSTATE_HANDLER_COUNT                3
#define DLL1B5_SEQUENCE_ID_SC_LIGHTFOOT              0x27B
#define DLL1B5_SEQUENCE_ID_SC_BABY_LIGHTFOOT         0x27C
#define DLL1B5_COMPLETION_GAMEBIT_SC_TOTEM_BOND      0x64C

typedef int (*LightfootStateHandler)(GameObject* obj, BaddieState* state, f32 timeDelta);
typedef int (*LightfootSubstateHandler)(GameObject* obj, BaddieState* state);

typedef struct LightfootPlacement {
    ObjPlacement base;
    u8 unknown18[2];
    union {
        s16 behaviorId;
        s16 completionGameBit;
    };
    s16 eventGameBit;
    u8 unknown1E[0x28 - 0x1E];
    s8 objectFlags;
    u8 unknown29[0x30 - 0x29];
    s16 activeGameBit;
} LightfootPlacement;

typedef struct LightfootControlState {
    const s16* moveIds;
    const f32* moveSpeeds;
    f32 completionTimer;
    f32 pulseTimer;
    f32 lifeTimer;
    f32 wanderTimer;
    u8 unknown18[0x1E - 0x18];
    u16 targetSector;
    u16 targetYawDelta;
    u16 targetDistance;
    u16 moveIndex;
    s16 weaponDefNoSentinel;
    s16 weaponDefNo;
    u16 movementSfxId;
    u8 completionCountdown;
    u8 unknown2D;
    u8 challengeCompletePending;
    u8 unknown2F;
} LightfootControlState;

typedef struct LightfootButtonTimingControlState {
    const s16* moveIds;
    const f32* moveSpeeds;
    f32 completionTimer;
    f32 pulseTimer;
    f32 lifeTimer;
    f32 wanderTimer;
    u16 phase;
    u16 previousPhase2;
    u16 previousPhase;
    u8 unknown1E[0x24 - 0x1E];
    u16 animationIndex;
    u8 unknown26[0x2D - 0x26];
    u8 difficulty;
} LightfootButtonTimingControlState;

typedef struct LightfootState {
    GroundBaddieState groundBaddie;
    u8 unknown410[sizeof(LightfootControlState)];
} LightfootState;

STATIC_ASSERT(offsetof(LightfootPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(LightfootPlacement, behaviorId) == 0x1A);
STATIC_ASSERT(offsetof(LightfootPlacement, completionGameBit) == 0x1A);
STATIC_ASSERT(offsetof(LightfootPlacement, eventGameBit) == 0x1C);
STATIC_ASSERT(offsetof(LightfootPlacement, objectFlags) == 0x28);
STATIC_ASSERT(offsetof(LightfootPlacement, activeGameBit) == 0x30);

STATIC_ASSERT(offsetof(LightfootControlState, moveIds) == 0x00);
STATIC_ASSERT(offsetof(LightfootControlState, moveSpeeds) == 0x04);
STATIC_ASSERT(offsetof(LightfootControlState, completionTimer) == 0x08);
STATIC_ASSERT(offsetof(LightfootControlState, pulseTimer) == 0x0C);
STATIC_ASSERT(offsetof(LightfootControlState, lifeTimer) == 0x10);
STATIC_ASSERT(offsetof(LightfootControlState, wanderTimer) == 0x14);
STATIC_ASSERT(offsetof(LightfootControlState, targetSector) == 0x1E);
STATIC_ASSERT(offsetof(LightfootControlState, targetYawDelta) == 0x20);
STATIC_ASSERT(offsetof(LightfootControlState, targetDistance) == 0x22);
STATIC_ASSERT(offsetof(LightfootControlState, moveIndex) == 0x24);
STATIC_ASSERT(offsetof(LightfootControlState, weaponDefNoSentinel) == 0x26);
STATIC_ASSERT(offsetof(LightfootControlState, weaponDefNo) == 0x28);
STATIC_ASSERT(offsetof(LightfootControlState, movementSfxId) == 0x2A);
STATIC_ASSERT(offsetof(LightfootControlState, challengeCompletePending) == 0x2E);
STATIC_ASSERT(sizeof(LightfootControlState) == 0x30);
STATIC_ASSERT(offsetof(LightfootControlState, completionCountdown) == 0x2C);

STATIC_ASSERT(offsetof(LightfootButtonTimingControlState, phase) == offsetof(LightfootControlState, unknown18));
STATIC_ASSERT(offsetof(LightfootButtonTimingControlState, previousPhase2) == offsetof(LightfootControlState, unknown18) + 2);
STATIC_ASSERT(offsetof(LightfootButtonTimingControlState, previousPhase) == offsetof(LightfootControlState, unknown18) + 4);
STATIC_ASSERT(offsetof(LightfootButtonTimingControlState, animationIndex) == offsetof(LightfootControlState, moveIndex));
STATIC_ASSERT(offsetof(LightfootButtonTimingControlState, difficulty) == offsetof(LightfootControlState, unknown2D));
STATIC_ASSERT(sizeof(LightfootButtonTimingControlState) == sizeof(LightfootControlState));

STATIC_ASSERT(sizeof(LightfootState) == 0x440);
STATIC_ASSERT(offsetof(LightfootState, groundBaddie) == 0x000);
STATIC_ASSERT(offsetof(LightfootState, unknown410) == 0x410);

extern LightfootStateHandler gLightfootStateHandlers[DLL1B5_STATE_HANDLER_COUNT];
extern LightfootSubstateHandler gLightfootSubstateHandlers[DLL1B5_SUBSTATE_HANDLER_COUNT];

extern s16 gLightfootMoveIds0[2];
extern f32 gLightfootMoveSpeeds0[2];
extern s16 gLightfootMoveIds1[2];
extern f32 gLightfootMoveSpeeds1[2];
extern s16 gLightfootMoveIds2[2];
extern f32 gLightfootMoveSpeeds2[2];
extern s16 gLightfootMoveIds3[2];
extern f32 gLightfootMoveSpeeds3[2];
extern s16 gLightfootMoveIds4[2];
extern f32 gLightfootMoveSpeeds4[2];


int Lightfoot_getExtraSize(void);
int Lightfoot_getObjectTypeId(void);
void Lightfoot_free(GameObject* obj, int preserveChildren);
void Lightfoot_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void Lightfoot_hitDetect(void);
void Lightfoot_update(GameObject* obj);
void Lightfoot_init(GameObject* obj, const LightfootPlacement* placement, int isReload);
void Lightfoot_release(void);
void Lightfoot_initialise(void);

extern ObjectDescriptor gLightfootObjDescriptor;

#endif /* DLLS_OBJECTS_437_H_ */
