#ifndef MAIN_DLL_DLL_02AF_TREE_H
#define MAIN_DLL_DLL_02AF_TREE_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

#define TREE_AMBIENT_EFFECT_COUNT      3
#define TREE_AMBIENT_EFFECT_SETUP_SIZE 0x28

typedef struct TreeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 flagsLo;
    u8 proximityRadiusHalf;
    u8 flagsHi;
    u8 pad1F;
    u8 colorR;
    u8 colorG;
    u8 colorB;
} TreeSetup;

typedef struct TreeAmbientEffectSetup
{
    ObjPlacement base;
    int sourceObject;
    u16 animFrame;
    s16 unk1E;
    u8 colorA[3];
    u8 colorB[2];
    s8 verticalDrift;
    s16 modelId;
} TreeAmbientEffectSetup;

typedef struct TreeState
{
    int ambientEffectHandles[TREE_AMBIENT_EFFECT_COUNT];
    f32 ambientEffectPos[TREE_AMBIENT_EFFECT_COUNT][3];
    f32 ambientSpawnTimers[TREE_AMBIENT_EFFECT_COUNT];
    f32 playerBurstCooldown;
    f32 ambientBurstTimer;
    f32 swayTimer;
    f32 scale;
    f32 hitCooldownTimer;
    f32 hitEffectCooldown;
    u16 proximityRadius;
    u16 lastPlayerDistance;
    u16 flags;
    u16 effectProfileIndex;
} TreeState;

STATIC_ASSERT(offsetof(TreeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(TreeSetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(TreeSetup, flagsLo) == 0x1c);
STATIC_ASSERT(offsetof(TreeSetup, proximityRadiusHalf) == 0x1d);
STATIC_ASSERT(offsetof(TreeSetup, flagsHi) == 0x1e);
STATIC_ASSERT(offsetof(TreeSetup, colorR) == 0x20);
STATIC_ASSERT(offsetof(TreeSetup, colorB) == 0x22);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, sourceObject) == 0x18);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, animFrame) == 0x1c);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, colorA) == 0x20);
STATIC_ASSERT(sizeof(TreeAmbientEffectSetup) == TREE_AMBIENT_EFFECT_SETUP_SIZE);
STATIC_ASSERT(offsetof(TreeState, ambientEffectPos) == 0xc);
STATIC_ASSERT(offsetof(TreeState, ambientSpawnTimers) == 0x30);
STATIC_ASSERT(offsetof(TreeState, playerBurstCooldown) == 0x3c);
STATIC_ASSERT(offsetof(TreeState, scale) == 0x48);
STATIC_ASSERT(offsetof(TreeState, hitEffectCooldown) == 0x50);
STATIC_ASSERT(offsetof(TreeState, proximityRadius) == 0x54);
STATIC_ASSERT(offsetof(TreeState, lastPlayerDistance) == 0x56);
STATIC_ASSERT(offsetof(TreeState, flags) == 0x58);
STATIC_ASSERT(sizeof(TreeState) == 0x5c);

extern f32 gTreeEffectColors[];
extern const f32 gTreeScaleByteNormalizer;
extern const f32 lbl_803E72F8;
extern const f32 lbl_803E7308;
extern const f32 lbl_803E730C;
extern const f32 lbl_803E7310;
extern const f32 lbl_803E7314;
extern const f32 lbl_803E7318;
extern const f32 lbl_803E731C;
extern const f32 lbl_803E7320;
extern const f32 lbl_803E7324;
extern const f32 lbl_803E732C;

extern ObjectDescriptor gTreeObjDescriptor;

int tree_getExtraSize(void);
void tree_spawnAmbientEffect(GameObject* obj, TreeState* state, s8 index);
void tree_updateAmbientEffects(GameObject* obj, TreeState* state);
void tree_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void tree_init(GameObject* obj, TreeSetup* setup);
void tree_update(GameObject* obj);

#endif
