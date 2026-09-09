#ifndef DLLS_OBJECTS_689_CMBSRC_H_
#define DLLS_OBJECTS_689_CMBSRC_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"

#define CMBSRC_PLACEMENT_BYTES 0x30
#define CMBSRC_EXTRA_STATE_BYTES 0x28

#define CMBSRC_OBJECT_ID 0x06E8

#define CMBSRC_MAP_EMIT_WHEN_UNRENDERED 0x01

#define CMBSRC_COLOR_CYCLE_COUNT 3

#define CMBSRC_COLOR_COUNT 16
#define CMBSRC_COLOR_BANK_COUNT 2

struct ModelLightStruct;

/* Full placement used by SC_Cloudrun's 0x30-byte allocation. DFP_RotateP
 * instead requests and clears 0x2C bytes; its enabled glow still reads +0x2C
 * from uninitialized slack in the allocator's rounded 0x40-byte block.
 * This full-record type does not describe that short producer's extent. */
typedef struct CmbSrcPlacement {
  ObjPlacement base;
  u8 rotZ;
  u8 rotY;
  u8 rotX;
  u8 colorIndex;
  u8 effectMode;
  u8 pulseSubMode;
  u8 unknown1E[0x20 - 0x1E];
  f32 radius;
  s16 gameBit;
  u8 colorDistance;
  u8 effectDistance;
  union {
    u8 pulseDistance;       /* Ordinary source: maximum pulse distance / 8. */
    u8 thrusterEmissionParam;  /* Normalized parameter passed to objfx_spawnLightPulse. */
  } modeParam;
  u8 flags;
  u8 behaviorFlags;
  u8 inactiveSeconds;
  u8 glowProjectionMode;
  u8 unknown2D[CMBSRC_PLACEMENT_BYTES - 0x2D];
} CmbSrcPlacement;

/* MWCC stores this one-bit field in bit 7 of the final state byte. */
typedef struct CmbSrcHitFlags {
  u8 disabled : 1;
} CmbSrcHitFlags;

/* cmbsrc_getExtraSize returns 0x28 bytes. */
typedef struct CmbSrcState {
  struct ModelLightStruct *light;
  f32 effectTimer;
  f32 pulseTimer;
  f32 particleTimer;
  f32 colorCycleTimer;
  f32 inactiveTimer;
  f32 radius;
  f32 hitRecoverTimer;
  u16 inactiveFrameCount;
  u8 flags;
  u8 colorCycleIndex;
  u8 priorityHitType;
  u8 active;
  s8 hitCharge;
  CmbSrcHitFlags hitFlags;
} CmbSrcState;

STATIC_ASSERT(sizeof(CmbSrcPlacement) == CMBSRC_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(CmbSrcPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(CmbSrcPlacement, rotZ) == 0x18);
STATIC_ASSERT(offsetof(CmbSrcPlacement, rotY) == 0x19);
STATIC_ASSERT(offsetof(CmbSrcPlacement, rotX) == 0x1A);
STATIC_ASSERT(offsetof(CmbSrcPlacement, colorIndex) == 0x1B);
STATIC_ASSERT(offsetof(CmbSrcPlacement, effectMode) == 0x1C);
STATIC_ASSERT(offsetof(CmbSrcPlacement, pulseSubMode) == 0x1D);
STATIC_ASSERT(offsetof(CmbSrcPlacement, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(CmbSrcPlacement, radius) == 0x20);
STATIC_ASSERT(offsetof(CmbSrcPlacement, gameBit) == 0x24);
STATIC_ASSERT(offsetof(CmbSrcPlacement, colorDistance) == 0x26);
STATIC_ASSERT(offsetof(CmbSrcPlacement, effectDistance) == 0x27);
STATIC_ASSERT(offsetof(CmbSrcPlacement, modeParam.pulseDistance) == 0x28);
STATIC_ASSERT(offsetof(CmbSrcPlacement, modeParam.thrusterEmissionParam) == 0x28);
STATIC_ASSERT(offsetof(CmbSrcPlacement, flags) == 0x29);
STATIC_ASSERT(offsetof(CmbSrcPlacement, behaviorFlags) == 0x2A);
STATIC_ASSERT(offsetof(CmbSrcPlacement, inactiveSeconds) == 0x2B);
STATIC_ASSERT(offsetof(CmbSrcPlacement, glowProjectionMode) == 0x2C);
STATIC_ASSERT(offsetof(CmbSrcPlacement, unknown2D) == 0x2D);

STATIC_ASSERT(sizeof(CmbSrcHitFlags) == 1);
STATIC_ASSERT(sizeof(CmbSrcState) == CMBSRC_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(CmbSrcState, light) == 0x00);
STATIC_ASSERT(offsetof(CmbSrcState, effectTimer) == 0x04);
STATIC_ASSERT(offsetof(CmbSrcState, pulseTimer) == 0x08);
STATIC_ASSERT(offsetof(CmbSrcState, particleTimer) == 0x0C);
STATIC_ASSERT(offsetof(CmbSrcState, colorCycleTimer) == 0x10);
STATIC_ASSERT(offsetof(CmbSrcState, inactiveTimer) == 0x14);
STATIC_ASSERT(offsetof(CmbSrcState, radius) == 0x18);
STATIC_ASSERT(offsetof(CmbSrcState, hitRecoverTimer) == 0x1C);
STATIC_ASSERT(offsetof(CmbSrcState, inactiveFrameCount) == 0x20);
STATIC_ASSERT(offsetof(CmbSrcState, flags) == 0x22);
STATIC_ASSERT(offsetof(CmbSrcState, colorCycleIndex) == 0x23);
STATIC_ASSERT(offsetof(CmbSrcState, priorityHitType) == 0x24);
STATIC_ASSERT(offsetof(CmbSrcState, active) == 0x25);
STATIC_ASSERT(offsetof(CmbSrcState, hitCharge) == 0x26);
STATIC_ASSERT(offsetof(CmbSrcState, hitFlags) == 0x27);

/* Only the first three bytes are selected by the cycling code. */
typedef struct CmbSrcColorCycleTable {
  u8 indices[CMBSRC_COLOR_CYCLE_COUNT];
  u8 unknown03[5];
} CmbSrcColorCycleTable;

STATIC_ASSERT(sizeof(CmbSrcColorCycleTable) == 8);
STATIC_ASSERT(offsetof(CmbSrcColorCycleTable, indices) == 0);
STATIC_ASSERT(offsetof(CmbSrcColorCycleTable, unknown03) == 3);

extern ObjectDescriptor gCmbSrcObjDescriptor;
extern CmbSrcColorCycleTable gCmbsrcColorCycleIndexTable;
extern u8 gCmbsrcColorSoundIdTable[CMBSRC_COLOR_COUNT];
extern u8 gCmbsrcColorRgbTable[CMBSRC_COLOR_BANK_COUNT][CMBSRC_COLOR_COUNT][3];
extern f32 gCmbsrcColorRadiusScaleTable[CMBSRC_COLOR_COUNT];

int cmbsrc_getExtraSize(void);
int cmbsrc_getObjectTypeId(void);
void cmbsrc_initialise(void);
void cmbsrc_release(void);
int cmbsrc_updateAndReturnZero(GameObject* obj);
/* Returns the cycle ordinal (0..2), or -1 for a non-cycling source. */
int cmbsrc_getColorCycleIndex(GameObject* obj);
/* Controls the render-visibility gate; distance and timer gates still apply. */
void cmbsrc_setEmitWhenUnrendered(GameObject* obj, u8 emitWhenUnrendered);
void cmbsrc_free(GameObject* cmbsrc);
void cmbsrc_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
u8 cmbsrc_shouldActivate(GameObject* obj, CmbSrcState* state, CmbSrcPlacement* setup);
u8 cmbsrc_shouldDeactivate(GameObject* obj, CmbSrcState* state, CmbSrcPlacement* setup);
void cmbsrc_hitDetect(GameObject* obj);
u8 cmbsrc_cycleColor(GameObject* obj, CmbSrcState* state);
void cmbsrc_updateVisuals(GameObject* obj, CmbSrcState* state);
void cmbsrc_update(GameObject* obj);
void cmbsrc_init(GameObject* obj, CmbSrcPlacement* setup);

#endif /* DLLS_OBJECTS_689_CMBSRC_H_ */
