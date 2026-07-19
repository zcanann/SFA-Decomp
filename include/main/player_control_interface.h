#ifndef MAIN_PLAYER_CONTROL_INTERFACE_H_
#define MAIN_PLAYER_CONTROL_INTERFACE_H_

#include "global.h"

typedef struct PlayerControlInterface {
    u8 pad00[0x04];
    void (*init)(void *unused, void *state, int moveA, int moveB);
    void (*update)(void *obj, void *state, f32 timeDelta, f32 pathDelta, void *stateHandlers,
                   void *substateHandlers);
    void (*updateVelocityState)(void *obj, void *state, void *stateHandlers);
    void (*setOverride)(u32 obj);
    void (*setState)(void *obj, void *state, int newState);
    void (*followCurve)(void *obj, void *state, f32 x, f32 z, f32 timeDelta, int flag);
    void (*moveTowardPoint)(void *obj, void *state, f32 x, f32 z, f32 minDistance, f32 maxDistance,
                            f32 speed);
    void (*updateAnimRootMotion)(void *obj, void *state, f32 timeDelta, u32 flags);
    void (*updateTurnFromRootMotion)(void *obj, void *state, f32 timeDelta, f32 scale, f32 limit);
    void (*applyModelForwardVelocity)(void *obj, void *state, f32 timeDelta, f32 scale);
    void (*applyYawForwardVelocity)(void *obj, void *state, f32 timeDelta, f32 scale);
    void (*rotateTowardTarget)(void *obj, void *state, int speed);
    void (*playSoundOnEvent0F)(void *obj, void *state, int eventBit, int sfxIndex, void *sfxTable);
    void (*playSoundOnEvent10)(void *obj, void *state, int eventBit, int sfxIndex, void *sfxTable);
    void (*findCurve)(void *obj, void *state, int curveId);
    void (*updateCurve)(void *obj, void *state, f32 timeDelta);
    void (*applyDirectionalVelocity)(void *obj, void *state, int angle, f32 timeDelta, f32 scale);
    void (*clearXZVelocity)(void *obj, void *state);
    void (*setAnimIds)(int unused1, int unused2, u32 moveA, u32 moveB);
    void (*updateSecondaryBlendMove)(void *obj, void *state, int moveA, int moveB);
    void (*spawnProjGfx)(void *obj, void *state, int effectId, int count, int unused, int mode);
    void (*spawnPartfx)(void *obj, void *state, int effectId, int count, int mode);
} PlayerControlInterface;

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
STATIC_ASSERT(offsetof(PlayerControlInterface, applyModelForwardVelocity) == 0x28);
STATIC_ASSERT(offsetof(PlayerControlInterface, applyYawForwardVelocity) == 0x2C);
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

#endif /* MAIN_PLAYER_CONTROL_INTERFACE_H_ */
