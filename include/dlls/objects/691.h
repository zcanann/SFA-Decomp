#ifndef DLLS_OBJECTS_691_H_
#define DLLS_OBJECTS_691_H_

#include "global.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

/* active occupies the high bit of the state byte under MWCC. Assigning a
 * game-bit value retains its low bit rather than testing it for nonzero. */
typedef struct VortexFlags {
    u8 active : 1;
    u8 unknown : 7;
} VortexFlags;

/* Vortex_getExtraSize returns the required 0x28 bytes. Up to three layers
 * are used; the WndLift variants initialize and render only two. */
typedef struct VortexState {
    f32 activationFade;
    f32 particleTimer;
    f32 layerAlphaScale[3];
    f32 layerScale[3];
    s16 layerAngles[3];
    VortexFlags flags;
    u8 unknown27;
} VortexState;

/* Reader prefix through +0x21. EN serialized extent is not established;
 * secondary EN rev1 / JP records are 0x24 bytes. Never use this reader's
 * sizeof as an allocation or copy size. */
typedef struct VortexPlacementPrefix {
    ObjPlacement base;
    u8 unknown18[2];
    s16 windLiftScaleQ14; /* Signed multiplier divided by 16384 for WndLift. */
    s16 reverseTextureScroll;
    union {
        s16 reverseScrollGameBit;      /* WndLift: toggles scroll direction. */
        s16 suppressActivationGameBit; /* Default init / SkyVort update. */
    } control;
    s16 activeGameBit;
} VortexPlacementPrefix;

STATIC_ASSERT(sizeof(VortexFlags) == 1);
STATIC_ASSERT(sizeof(VortexState) == 0x28);
STATIC_ASSERT(offsetof(VortexState, activationFade) == 0x00);
STATIC_ASSERT(offsetof(VortexState, particleTimer) == 0x04);
STATIC_ASSERT(offsetof(VortexState, layerAlphaScale) == 0x08);
STATIC_ASSERT(offsetof(VortexState, layerScale) == 0x14);
STATIC_ASSERT(offsetof(VortexState, layerAngles) == 0x20);
STATIC_ASSERT(offsetof(VortexState, flags) == 0x26);
STATIC_ASSERT(offsetof(VortexState, unknown27) == 0x27);

STATIC_ASSERT(offsetof(VortexPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, unknown18) == 0x18);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, windLiftScaleQ14) == 0x1A);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, reverseTextureScroll) == 0x1C);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, control.reverseScrollGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, control.suppressActivationGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VortexPlacementPrefix, activeGameBit) == 0x20);

/* Three indexed layer speeds followed by two unaccessed bytes. */
typedef struct VortexLayerSpeedTable {
    s16 speeds[3];
    u8 unknown06[2];
} VortexLayerSpeedTable;

STATIC_ASSERT(sizeof(VortexLayerSpeedTable) == 8);
STATIC_ASSERT(offsetof(VortexLayerSpeedTable, speeds) == 0);
STATIC_ASSERT(offsetof(VortexLayerSpeedTable, unknown06) == 6);

extern ObjectDescriptor gVortexObjDescriptor;
extern VortexLayerSpeedTable gVortexAngleSpeed83D;
extern VortexLayerSpeedTable gVortexAngleSpeedDefault;
extern s16 gVortexAngleSpeed835[2];
extern s16 gVortexRotZTable[2];
extern f32 gVortexScaleParams[4][3];
extern f32 gVortexRadiusScaleInit[2];
extern f32 gVortexAlphaScaleInit835[2];
extern f32 gVortexAlphaScaleInit838[2];

int Vortex_getExtraSize(void);
int Vortex_getObjectTypeId(void);
void Vortex_free(GameObject* obj);
void Vortex_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Vortex_hitDetect(void);
void Vortex_init(GameObject* obj, VortexPlacementPrefix* setup);
void Vortex_update(GameObject* obj);
void Vortex_release(void);
void Vortex_initialise(void);

#endif
