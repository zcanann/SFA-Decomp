#ifndef MAIN_OBJHITS_TYPES_H_
#define MAIN_OBJHITS_TYPES_H_

#include "global.h"
#include "ghidra_import.h"

#define OBJHITS_PRIORITY_HIT_COUNT 3

/*
 * ObjHitsPriorityState.contactFlags (state+0xAD s8) contact-kind markers.
 * The producer objhits.c sets exactly one per contact based on the struck
 * hit-volume's kind: kind==0 -> KIND0, kind!=0 -> KIND_NONZERO. Consumers
 * (dll object states) read the nonzero-kind bit and the nonzero-ness of the
 * field. Field is s8, so a bare int constant folds identically.
 */
#define OBJHITS_CONTACT_FLAG_KIND0        0x1 /* contact with a kind-0 hit volume */
#define OBJHITS_CONTACT_FLAG_KIND_NONZERO 0x2 /* contact with a nonzero-kind hit volume */

typedef struct ObjHitsPriorityState {
  u8 pad00[0x0C];
  f32 primaryRadiusSquared;
  f32 localPosX;
  f32 localPosY;
  f32 localPosZ;
  f32 worldPosX;
  f32 worldPosY;
  f32 worldPosZ;
  f32 primaryRadiusY;
  f32 primaryRadiusXZ;
  f32 secondaryRadiusY;
  f32 secondaryRadiusXZ;
  f32 sweepRadiusX;
  f32 contactPosX;
  f32 contactPosY;
  f32 contactPosZ;
  u32 objectHitMask;
  u32 skeletonHitMask;
  u32 lastHitObject;
  u8 pad54[0x58 - 0x54];
  s16 capsuleScale;
  s16 primaryRadius;
  s16 primaryCapsuleOffsetA;
  s16 primaryCapsuleOffsetB;
  s16 flags;
  u8 shapeFlags;
  u8 pad63;
  s16 secondaryRadius;
  s16 secondaryCapsuleOffsetA;
  s16 secondaryCapsuleOffsetB;
  u8 lateralResponseWeight;
  u8 axialResponseWeight;
  s8 objectPairPriority;
  u8 objectPairHitVolume;
  s8 hitVolumePriority;
  s8 hitVolumeId;
  u8 suppressOutgoingHits;
  s8 priorityHitCount;
  s8 sphereIndices[OBJHITS_PRIORITY_HIT_COUNT];
  s8 priorities[OBJHITS_PRIORITY_HIT_COUNT];
  u8 hitVolumes[OBJHITS_PRIORITY_HIT_COUNT];
  u8 pad7B;
  int hitObjects[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosX[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosY[OBJHITS_PRIORITY_HIT_COUNT];
  f32 hitPosZ[OBJHITS_PRIORITY_HIT_COUNT];
  s8 contactHitVolume;
  s8 contactFlags;
  u8 activeHitboxMode;
  u8 resetHitboxMode;
  u8 stateIndex;
  u8 padB1;
  u16 trackContactMask;
  u8 sourceMask;
  u8 targetMask;
  u8 secondaryShapeFlags;
} ObjHitsPriorityState;

STATIC_ASSERT(offsetof(ObjHitsPriorityState, activeHitboxMode) == 0xAE);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, resetHitboxMode) == 0xAF);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, stateIndex) == 0xB0);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryRadiusSquared) == 0x0C);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, localPosX) == 0x10);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, worldPosX) == 0x1C);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryRadiusY) == 0x28);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryRadiusXZ) == 0x2C);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryRadiusY) == 0x30);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryRadiusXZ) == 0x34);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, sweepRadiusX) == 0x38);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, objectHitMask) == 0x48);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, skeletonHitMask) == 0x4C);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, lastHitObject) == 0x50);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, capsuleScale) == 0x58);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryRadius) == 0x5A);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryCapsuleOffsetA) == 0x5C);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, primaryCapsuleOffsetB) == 0x5E);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, flags) == 0x60);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, shapeFlags) == 0x62);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryRadius) == 0x64);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryCapsuleOffsetA) == 0x66);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryCapsuleOffsetB) == 0x68);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, lateralResponseWeight) == 0x6A);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, axialResponseWeight) == 0x6B);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, suppressOutgoingHits) == 0x70);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, priorityHitCount) == 0x71);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, contactFlags) == 0xAD);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, trackContactMask) == 0xB2);
STATIC_ASSERT(offsetof(ObjHitsPriorityState, secondaryShapeFlags) == 0xB6);

#endif
