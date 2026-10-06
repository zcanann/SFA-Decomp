#ifndef MAIN_PLAYER_CONTROL_INTERFACE_H_
#define MAIN_PLAYER_CONTROL_INTERFACE_H_

#include "global.h"
#include "game/objects/object_fwd.h"

typedef struct BaddieState BaddieState;

typedef struct PlayerControlInterface {
    u32 reserved;
    void (*init)(GameObject* unused, BaddieState* state, int moveA, int moveB);
    void (*update)(GameObject* obj, BaddieState* state, f32 timeDelta, f32 pathDelta, void *stateHandlers,
                   void *substateHandlers);
    void (*updateVelocityState)(GameObject* obj, BaddieState* state, void *stateHandlers);
    void (*setOverride)(GameObject* obj);
    void (*setState)(GameObject* obj, BaddieState* state, int newState);
    void (*followCurve)(GameObject* obj, BaddieState* state, f32 x, f32 z, f32 timeDelta, int flag);
    void (*moveTowardPoint)(GameObject* obj, BaddieState* state, f32 x, f32 z, f32 minDistance, f32 maxDistance,
                            f32 speed);
    void (*updateAnimRootMotion)(GameObject* obj, BaddieState* state, f32 timeDelta, int flags);
    void (*updateTurnFromRootMotion)(GameObject* obj, BaddieState* state, f32 timeDelta, f32 scale, f32 limit);
    void (*applyPositionNudge)(GameObject* obj, BaddieState* state, f32 timeDelta, f32 scale);
    void (*applyYawNudge)(GameObject* obj, BaddieState* state, f32 timeDelta, f32 scale);
    void (*rotateTowardTarget)(GameObject* obj, BaddieState* state, f32 timeDelta, int speed);
    void (*playSoundOnEvent0F)(GameObject* obj, BaddieState* state, int eventBit, int sfxIndex, int* sfxTable);
    void (*playSoundOnEvent10)(GameObject* obj, BaddieState* state, int eventBit, int sfxIndex, int* sfxTable);
    void (*findCurve)(GameObject* obj, BaddieState* state, int curveId);
    void (*updateCurve)(GameObject* obj, BaddieState* state, f32 timeDelta);
    void (*applyDirectionalVelocity)(GameObject* obj, BaddieState* state, f32 timeDelta, f32 scale, int angle);
    void (*clearXZVelocity)(GameObject* obj, BaddieState* state);
    void (*setAnimIds)(GameObject* unusedObj, BaddieState* unusedState, u32 moveA, u32 moveB);
    void (*updateSecondaryBlendMove)(GameObject* obj, BaddieState* state, int moveA, int moveB);
    void (*spawnProjGfx)(GameObject* obj, BaddieState* state, int effectId, int count, int unused, int mode);
    void (*spawnPartfx)(GameObject* obj, BaddieState* state, int effectId, int count, int mode);
    void (*unused)(void);
} PlayerControlInterface;

typedef struct PlayerControlDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    PlayerControlInterface interface;
} PlayerControlDescriptor;

extern PlayerControlDescriptor player_funcs;

extern PlayerControlInterface **gPlayerInterface;

STATIC_ASSERT(offsetof(PlayerControlInterface, init) == 0x04);
STATIC_ASSERT(offsetof(PlayerControlInterface, update) == 0x08);
STATIC_ASSERT(offsetof(PlayerControlInterface, updateVelocityState) == 0x0C);
STATIC_ASSERT(offsetof(PlayerControlInterface, setOverride) == 0x10);
STATIC_ASSERT(offsetof(PlayerControlInterface, setState) == 0x14);
STATIC_ASSERT(offsetof(PlayerControlInterface, followCurve) == 0x18);
STATIC_ASSERT(offsetof(PlayerControlInterface, moveTowardPoint) == 0x1C);
STATIC_ASSERT(offsetof(PlayerControlInterface, updateAnimRootMotion) == 0x20);
STATIC_ASSERT(offsetof(PlayerControlInterface, updateTurnFromRootMotion) == 0x24);
STATIC_ASSERT(offsetof(PlayerControlInterface, applyPositionNudge) == 0x28);
STATIC_ASSERT(offsetof(PlayerControlInterface, applyYawNudge) == 0x2C);
STATIC_ASSERT(offsetof(PlayerControlInterface, rotateTowardTarget) == 0x30);
STATIC_ASSERT(offsetof(PlayerControlInterface, playSoundOnEvent0F) == 0x34);
STATIC_ASSERT(offsetof(PlayerControlInterface, playSoundOnEvent10) == 0x38);
STATIC_ASSERT(offsetof(PlayerControlInterface, findCurve) == 0x3C);
STATIC_ASSERT(offsetof(PlayerControlInterface, updateCurve) == 0x40);
STATIC_ASSERT(offsetof(PlayerControlInterface, applyDirectionalVelocity) == 0x44);
STATIC_ASSERT(offsetof(PlayerControlInterface, clearXZVelocity) == 0x48);
STATIC_ASSERT(offsetof(PlayerControlInterface, setAnimIds) == 0x4C);
STATIC_ASSERT(offsetof(PlayerControlInterface, updateSecondaryBlendMove) == 0x50);
STATIC_ASSERT(offsetof(PlayerControlInterface, spawnProjGfx) == 0x54);
STATIC_ASSERT(offsetof(PlayerControlInterface, spawnPartfx) == 0x58);

STATIC_ASSERT(offsetof(PlayerControlInterface, unused) == 0x5C);
STATIC_ASSERT(sizeof(PlayerControlInterface) == 0x60);
STATIC_ASSERT(offsetof(PlayerControlDescriptor, interface) == 0x18);
STATIC_ASSERT(sizeof(PlayerControlDescriptor) == 0x78);

#endif /* MAIN_PLAYER_CONTROL_INTERFACE_H_ */
