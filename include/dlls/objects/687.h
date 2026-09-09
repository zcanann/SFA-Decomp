#ifndef DLLS_OBJECTS_687_H_
#define DLLS_OBJECTS_687_H_

#include "game/objects/object_fwd.h"
#include "dolphin/mtx/vec_types.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"

#define TREE_APPLE_COUNT         3
#define TREE_BURST_PROFILE_COUNT 11

/* Reader view only: the complete EN placement extent is not established.
 * Do not allocate or copy placements using sizeof this prefix. */
typedef struct TreePlacementPrefix {
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 flagsLo;
    u8 proximityRadiusHalf;
    u8 flagsHi;
    u8 pad1F;
} TreePlacementPrefix;

/* tree_getExtraSize allocates the complete 0x5C-byte state. */
typedef struct TreeState {
    GameObject* apples[TREE_APPLE_COUNT];
    f32 applePositions[TREE_APPLE_COUNT][3];
    f32 appleRespawnTimers[TREE_APPLE_COUNT];
    f32 playerBurstCooldown;
    f32 ambientBurstTimer;
    f32 swayAnimationStep;
    f32 scale;
    f32 hitCooldownTimer;
    f32 hitEffectCooldown;
    u16 proximityRadius;
    u16 lastPlayerDistance;
    u16 flags;
    u16 burstProfileIndex;
} TreeState;

STATIC_ASSERT(offsetof(TreePlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(TreePlacementPrefix, rotZ) == 0x18);
STATIC_ASSERT(offsetof(TreePlacementPrefix, rotY) == 0x19);
STATIC_ASSERT(offsetof(TreePlacementPrefix, rotX) == 0x1A);
STATIC_ASSERT(offsetof(TreePlacementPrefix, scale) == 0x1b);
STATIC_ASSERT(offsetof(TreePlacementPrefix, flagsLo) == 0x1c);
STATIC_ASSERT(offsetof(TreePlacementPrefix, proximityRadiusHalf) == 0x1d);
STATIC_ASSERT(offsetof(TreePlacementPrefix, flagsHi) == 0x1e);
STATIC_ASSERT(offsetof(TreeState, apples) == 0x00);
STATIC_ASSERT(offsetof(TreeState, applePositions) == 0xc);
STATIC_ASSERT(offsetof(TreeState, appleRespawnTimers) == 0x30);
STATIC_ASSERT(offsetof(TreeState, playerBurstCooldown) == 0x3c);
STATIC_ASSERT(offsetof(TreeState, ambientBurstTimer) == 0x40);
STATIC_ASSERT(offsetof(TreeState, swayAnimationStep) == 0x44);
STATIC_ASSERT(offsetof(TreeState, scale) == 0x48);
STATIC_ASSERT(offsetof(TreeState, hitCooldownTimer) == 0x4C);
STATIC_ASSERT(offsetof(TreeState, hitEffectCooldown) == 0x50);
STATIC_ASSERT(offsetof(TreeState, proximityRadius) == 0x54);
STATIC_ASSERT(offsetof(TreeState, lastPlayerDistance) == 0x56);
STATIC_ASSERT(offsetof(TreeState, flags) == 0x58);
STATIC_ASSERT(offsetof(TreeState, burstProfileIndex) == 0x5A);
STATIC_ASSERT(sizeof(TreeState) == 0x5c);

typedef struct TreeEffectBurst {
    Vec offset;
    f32 radius;
} TreeEffectBurst;

STATIC_ASSERT(offsetof(TreeEffectBurst, offset) == 0x00);
STATIC_ASSERT(offsetof(TreeEffectBurst, radius) == 0x0C);
STATIC_ASSERT(sizeof(TreeEffectBurst) == 0x10);

extern TreeEffectBurst gTreeEffectBursts[TREE_BURST_PROFILE_COUNT];

extern ObjectDescriptor gTreeObjDescriptor;

int tree_getExtraSize(void);
void tree_spawnApple(GameObject* obj, TreeState* state, s8 index);
void tree_updateApples(GameObject* obj, TreeState* state);
void tree_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void tree_init(GameObject* obj, TreePlacementPrefix* setup);
void tree_update(GameObject* obj);

#endif /* DLLS_OBJECTS_687_H_ */
