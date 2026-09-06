#ifndef DLLS_OBJECTS_346_H_
#define DLLS_OBJECTS_346_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define EXPLODABLE_FRAGMENT_COUNT 15
#define EXPLODABLE_RECIPE_COUNT   16

typedef enum ExplodableObjectGroup {
    EXPLODABLE_OBJECT_GROUP = 0x21,
} ExplodableObjectGroup;

typedef enum ExplodablePhase {
    EXPLODABLE_PHASE_WAIT = 0,
    EXPLODABLE_PHASE_BREAKING = 1,
    EXPLODABLE_PHASE_BROKEN = 2,
} ExplodablePhase;

typedef struct ExplodablePlacement {
    ObjPlacement base;
    u8 fragmentCount;
    u8 pad19;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 originX;
    s16 originY;
    s16 originZ;
    u8 pad26[0x06];
    s16 launchForce;
    s16 fragmentHeight;
    s16 secondaryLaunchScale;
    u8 pad32[0x06];
    u16 launchDelayBase;
    u8 pad3A[0x03];
    s8 scale;
    s16 doneGameBit;
    s16 activateGameBit;
    u8 pad42[0x06];
} ExplodablePlacement;

typedef struct ExplodableBreakRecipe {
    int sourceObjectId;
    int fragmentObjectId;
    int breakSfxId;
    u8 spinScale;
    u8 flags;
    u8 pad0E[0x02];
} ExplodableBreakRecipe;

typedef struct ExplodableChunk {
    u8 pad00[0x04];
    f32 centroidX;
    f32 centroidY;
    f32 centroidZ;
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    f32 spinX;
    f32 spinY;
    f32 spinZ;
    f32 secondarySpinX;
    f32 secondarySpinY;
    f32 secondarySpinZ;
    f32 secondaryVelocityX;
    f32 secondaryVelocityY;
    f32 secondaryVelocityZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 positionX;
    f32 positionY;
    f32 positionZ;
    f32 height;
    int launchDelayBase;
    int launchDelay;
    s16 rotZ;
    s16 rotY;
    s16 rotX;
    u8 gameBitMode;
    u8 unknown6B;
    u8 launchFlags;
    u8 spinScale;
    u8 pad6E[0x02];
} ExplodableChunk;

typedef struct ExplodableState {
    ExplodableChunk chunks[EXPLODABLE_FRAGMENT_COUNT];
    GameObject* children[EXPLODABLE_FRAGMENT_COUNT];
    u32 completedFragmentMask;
    int breakSfxId;
    u8 fragmentCount;
    u8 spawnedFlags[EXPLODABLE_FRAGMENT_COUNT];
    u8 phase;
    u8 recipeIndex;
    u8 pad6E6[0x02];
} ExplodableState;

STATIC_ASSERT(offsetof(ExplodablePlacement, base) == 0x00);
STATIC_ASSERT(offsetof(ExplodablePlacement, fragmentCount) == 0x18);
STATIC_ASSERT(offsetof(ExplodablePlacement, pad19) == 0x19);
STATIC_ASSERT(offsetof(ExplodablePlacement, rotX) == 0x1A);
STATIC_ASSERT(offsetof(ExplodablePlacement, rotY) == 0x1C);
STATIC_ASSERT(offsetof(ExplodablePlacement, rotZ) == 0x1E);
STATIC_ASSERT(offsetof(ExplodablePlacement, originX) == 0x20);
STATIC_ASSERT(offsetof(ExplodablePlacement, originY) == 0x22);
STATIC_ASSERT(offsetof(ExplodablePlacement, originZ) == 0x24);
STATIC_ASSERT(offsetof(ExplodablePlacement, pad26) == 0x26);
STATIC_ASSERT(offsetof(ExplodablePlacement, launchForce) == 0x2C);
STATIC_ASSERT(offsetof(ExplodablePlacement, fragmentHeight) == 0x2E);
STATIC_ASSERT(offsetof(ExplodablePlacement, secondaryLaunchScale) == 0x30);
STATIC_ASSERT(offsetof(ExplodablePlacement, pad32) == 0x32);
STATIC_ASSERT(offsetof(ExplodablePlacement, launchDelayBase) == 0x38);
STATIC_ASSERT(offsetof(ExplodablePlacement, pad3A) == 0x3A);
STATIC_ASSERT(offsetof(ExplodablePlacement, scale) == 0x3D);
STATIC_ASSERT(offsetof(ExplodablePlacement, doneGameBit) == 0x3E);
STATIC_ASSERT(offsetof(ExplodablePlacement, activateGameBit) == 0x40);
STATIC_ASSERT(offsetof(ExplodablePlacement, pad42) == 0x42);
STATIC_ASSERT(sizeof(ExplodablePlacement) == 0x48);

STATIC_ASSERT(offsetof(ExplodableBreakRecipe, sourceObjectId) == 0x00);
STATIC_ASSERT(offsetof(ExplodableBreakRecipe, fragmentObjectId) == 0x04);
STATIC_ASSERT(offsetof(ExplodableBreakRecipe, breakSfxId) == 0x08);
STATIC_ASSERT(offsetof(ExplodableBreakRecipe, spinScale) == 0x0C);
STATIC_ASSERT(offsetof(ExplodableBreakRecipe, flags) == 0x0D);
STATIC_ASSERT(offsetof(ExplodableBreakRecipe, pad0E) == 0x0E);
STATIC_ASSERT(sizeof(ExplodableBreakRecipe) == 0x10);

STATIC_ASSERT(offsetof(ExplodableChunk, centroidX) == 0x04);
STATIC_ASSERT(offsetof(ExplodableChunk, offsetX) == 0x10);
STATIC_ASSERT(offsetof(ExplodableChunk, spinX) == 0x1C);
STATIC_ASSERT(offsetof(ExplodableChunk, secondarySpinX) == 0x28);
STATIC_ASSERT(offsetof(ExplodableChunk, secondaryVelocityX) == 0x34);
STATIC_ASSERT(offsetof(ExplodableChunk, velocityX) == 0x40);
STATIC_ASSERT(offsetof(ExplodableChunk, positionX) == 0x4C);
STATIC_ASSERT(offsetof(ExplodableChunk, height) == 0x58);
STATIC_ASSERT(offsetof(ExplodableChunk, launchDelayBase) == 0x5C);
STATIC_ASSERT(offsetof(ExplodableChunk, launchDelay) == 0x60);
STATIC_ASSERT(offsetof(ExplodableChunk, rotZ) == 0x64);
STATIC_ASSERT(offsetof(ExplodableChunk, rotY) == 0x66);
STATIC_ASSERT(offsetof(ExplodableChunk, rotX) == 0x68);
STATIC_ASSERT(offsetof(ExplodableChunk, gameBitMode) == 0x6A);
STATIC_ASSERT(offsetof(ExplodableChunk, unknown6B) == 0x6B);
STATIC_ASSERT(offsetof(ExplodableChunk, launchFlags) == 0x6C);
STATIC_ASSERT(offsetof(ExplodableChunk, spinScale) == 0x6D);
STATIC_ASSERT(offsetof(ExplodableChunk, pad6E) == 0x6E);
STATIC_ASSERT(sizeof(ExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(ExplodableState, chunks) == 0x000);
STATIC_ASSERT(offsetof(ExplodableState, children) == 0x690);
STATIC_ASSERT(offsetof(ExplodableState, completedFragmentMask) == 0x6CC);
STATIC_ASSERT(offsetof(ExplodableState, breakSfxId) == 0x6D0);
STATIC_ASSERT(offsetof(ExplodableState, fragmentCount) == 0x6D4);
STATIC_ASSERT(offsetof(ExplodableState, spawnedFlags) == 0x6D5);
STATIC_ASSERT(offsetof(ExplodableState, phase) == 0x6E4);
STATIC_ASSERT(offsetof(ExplodableState, recipeIndex) == 0x6E5);
STATIC_ASSERT(offsetof(ExplodableState, pad6E6) == 0x6E6);
STATIC_ASSERT(sizeof(ExplodableState) == 0x6E8);

GameObject* explodable_spawnFragmentObject(GameObject* obj, int fragmentObjectId, ExplodableChunk* chunk,
                                           int fragmentIndex);
void explodable_buildFragments(GameObject* obj, ExplodablePlacement* placementAddress, int skipCentroid,
                               ExplodableState* stateAddress);
void explodable_computeFragmentLaunch(GameObject* obj, ExplodableChunk* chunk, ExplodablePlacement* placementAddress);
int explodable_getExtraSize(void);
void explodable_free(GameObject* obj, int keepChildren);
void explodable_render(void);
void explodable_update(GameObject* obj);
void explodable_init(GameObject* obj, ExplodablePlacement* placementAddress);

extern ExplodableBreakRecipe gExplodableBreakRecipeTable[EXPLODABLE_RECIPE_COUNT];
extern ObjectDescriptor gExplodableObjDescriptor;

#endif /* DLLS_OBJECTS_346_H_ */
