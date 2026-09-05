#ifndef DLLS_OBJECTS_609_DR_LASERCAN_H_
#define DLLS_OBJECTS_609_DR_LASERCAN_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/dll/DR/dr_types.h"
#include "main/dll/curve_walker.h"
#include "main/objprint_character_api.h"

/* All five EN romlist placements use nine words (0x24 bytes). */
typedef struct DrLaserCannonSetup {
    ObjPlacement base;
    s8 initialYaw;
    s8 reloadFrames;
    s16 targetRange;
    s16 beamSpeed;
    s16 destroyedGameBit;
    s16 warningOffGameBit;
    u8 pad22[2];
} DrLaserCannonSetup;

STATIC_ASSERT(offsetof(DrLaserCannonSetup, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, reloadFrames) == 0x19);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, targetRange) == 0x1a);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, beamSpeed) == 0x1c);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, destroyedGameBit) == 0x1e);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, warningOffGameBit) == 0x20);
STATIC_ASSERT(sizeof(DrLaserCannonSetup) == 0x24);

typedef struct DrLaserCannonState {
    int beamObject;
    u8 pad04[0x08];
    GameObject* lastHitObject;
    f32 muzzleX;
    f32 muzzleY;
    f32 muzzleZ;
    RomCurveWalker curveFollow;
    f32 animStepScale;
    int trickyCooldown;
    f32 reloadTimer;
    ObjJointTrackChannel aim[2];
    GameObject* warningObject;
    GameObject* firepipeObject;
    int activeFrames;
    int hitExcludeType;
    f32 bobOffset;
    s16 optionalGameBit;
    s8 health;
    u8 hasFirepipe;
    BitFlags8 flags;
    u8 pad1A9;
    u16 bobPhase;
} DrLaserCannonState;

STATIC_ASSERT(offsetof(DrLaserCannonState, beamObject) == 0x00);
STATIC_ASSERT(offsetof(DrLaserCannonState, lastHitObject) == 0x0c);
STATIC_ASSERT(offsetof(DrLaserCannonState, muzzleX) == 0x10);
STATIC_ASSERT(offsetof(DrLaserCannonState, muzzleY) == 0x14);
STATIC_ASSERT(offsetof(DrLaserCannonState, muzzleZ) == 0x18);
STATIC_ASSERT(offsetof(DrLaserCannonState, curveFollow) == 0x1c);
STATIC_ASSERT(offsetof(DrLaserCannonState, animStepScale) == 0x124);
STATIC_ASSERT(offsetof(DrLaserCannonState, trickyCooldown) == 0x128);
STATIC_ASSERT(offsetof(DrLaserCannonState, reloadTimer) == 0x12c);
STATIC_ASSERT(offsetof(DrLaserCannonState, aim) == 0x130);
STATIC_ASSERT(offsetof(DrLaserCannonState, warningObject) == 0x190);
STATIC_ASSERT(offsetof(DrLaserCannonState, firepipeObject) == 0x194);
STATIC_ASSERT(offsetof(DrLaserCannonState, activeFrames) == 0x198);
STATIC_ASSERT(offsetof(DrLaserCannonState, hitExcludeType) == 0x19c);
STATIC_ASSERT(offsetof(DrLaserCannonState, bobOffset) == 0x1a0);
STATIC_ASSERT(offsetof(DrLaserCannonState, optionalGameBit) == 0x1a4);
STATIC_ASSERT(offsetof(DrLaserCannonState, health) == 0x1a6);
STATIC_ASSERT(offsetof(DrLaserCannonState, hasFirepipe) == 0x1a7);
STATIC_ASSERT(offsetof(DrLaserCannonState, flags) == 0x1a8);
STATIC_ASSERT(offsetof(DrLaserCannonState, bobPhase) == 0x1aa);
STATIC_ASSERT(sizeof(DrLaserCannonState) == 0x1ac);

int DR_LaserCannon_getExtraSize(void);
int DR_LaserCannon_getObjectTypeId(void);
void DR_LaserCannon_initialise(void);
void DR_LaserCannon_release(void);
void DR_LaserCannon_free(GameObject* obj);
void DR_LaserCannon_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
GameObject* drlasercannon_getTrackedTarget(GameObject* obj, int* cooldown);
int drlasercannon_aimAtTarget(GameObject* self, GameObject* target, ObjJointTrackChannel* out, int maxRate,
                              f32* eyePos);
void DR_LaserCannon_init(GameObject* obj, DrLaserCannonSetup* setup);
void DR_LaserCannon_hitDetect(GameObject* obj);
void DR_LaserCannon_update(GameObject* obj);

extern ObjectDescriptor gDrLaserCannonObjDescriptor;
extern s16 gLaserCannonMaxAimStep;
extern f32 gLaserCannonAdvanceSpeed;
extern s16 gLaserCannonPitchStep;
extern f32 lbl_803DDD68;

#endif /* DLLS_OBJECTS_609_DR_LASERCAN_H_ */
