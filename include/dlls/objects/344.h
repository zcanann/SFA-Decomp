#ifndef DLLS_OBJECTS_344_H_
#define DLLS_OBJECTS_344_H_

#include "dlls/object_descriptor.h"
#include "main/vec_types.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/carryable_state.h"

typedef enum GunpowderBarrelObjectGroup {
    GUNPOWDER_BARREL_OBJECT_GROUP = 0x19,
    GUNPOWDER_BARREL_LOOSE_OBJECT_GROUP = 0x16,
} GunpowderBarrelObjectGroup;

typedef struct GunpowderBarrelPlacement {
    ObjPlacement base;
    u8 pad18;
    s8 disableRespawn;
    s16 generatorLinkId;
    s16 returnHome;
    s16 unknown1E;
    u8 pad20[0x04];
} GunpowderBarrelPlacement;

typedef struct GunpowderBarrelHeldFlags {
    u8 playerHeld : 1;
    u8 pendingThrowVelocityCapture : 1;
    u8 held : 1;
    u8 onGround : 1;
    u8 wasOnGround : 1;
    u8 landed : 1;
    u8 cannonRangeVariant : 1;
    u8 unknown01 : 1;
} GunpowderBarrelHeldFlags;

typedef struct GunpowderBarrelConfigFlags {
    u8 respawns : 1;
    u8 returnHome : 1;
    u8 unknown : 6;
} GunpowderBarrelConfigFlags;

typedef struct GunpowderBarrelState {
    CarryableState carryable;
    u8 pad0A[0x02];
    GameObject* queuedHitObject;
    GameObject* linkedTimerObject;
    u8 pad14;
    u8 heldByCarryInterface;
    u8 detonationTrigger;
    u8 fuseFrames;
    f32 respawnTimer;
    f32 releaseTimer;
    union {
        struct {
            f32 throwVelocityX;
            f32 throwVelocityY;
            f32 throwVelocityZ;
        };
        Vec3f throwVelocity;
    };
    f32 hitRadius;
    f32 unknown30;
    f32 radiusGrowthPerFrame;
    f32 accumulatedFallVelocity;
    s16 unknown3C;
    u8 unknown3E;
    u8 pad3F;
    int unknown40;
    s16 homingHeadingA;
    s16 homingHeadingB;
    GunpowderBarrelConfigFlags configFlags;
    u8 motionFlags;
    union {
        u8 heldFlagsRaw;
        GunpowderBarrelHeldFlags heldFlags;
    };
    u8 pad4B[0x05];
    s16 launchYaw;
    u8 pad52[0x02];
    f32 impactSoundCooldown;
} GunpowderBarrelState;

STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, pad18) == 0x18);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, disableRespawn) == 0x19);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, generatorLinkId) == 0x1A);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, returnHome) == 0x1C);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(GunpowderBarrelPlacement, pad20) == 0x20);
STATIC_ASSERT(sizeof(GunpowderBarrelPlacement) == 0x24);

STATIC_ASSERT(sizeof(GunpowderBarrelHeldFlags) == 0x01);
STATIC_ASSERT(sizeof(GunpowderBarrelConfigFlags) == 0x01);

STATIC_ASSERT(offsetof(GunpowderBarrelState, carryable) == 0x00);
STATIC_ASSERT(offsetof(GunpowderBarrelState, queuedHitObject) == 0x0C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, linkedTimerObject) == 0x10);
STATIC_ASSERT(offsetof(GunpowderBarrelState, pad14) == 0x14);
STATIC_ASSERT(offsetof(GunpowderBarrelState, heldByCarryInterface) == 0x15);
STATIC_ASSERT(offsetof(GunpowderBarrelState, detonationTrigger) == 0x16);
STATIC_ASSERT(offsetof(GunpowderBarrelState, fuseFrames) == 0x17);
STATIC_ASSERT(offsetof(GunpowderBarrelState, respawnTimer) == 0x18);
STATIC_ASSERT(offsetof(GunpowderBarrelState, releaseTimer) == 0x1C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, throwVelocityX) == 0x20);
STATIC_ASSERT(offsetof(GunpowderBarrelState, throwVelocityY) == 0x24);
STATIC_ASSERT(offsetof(GunpowderBarrelState, throwVelocityZ) == 0x28);
STATIC_ASSERT(offsetof(GunpowderBarrelState, hitRadius) == 0x2C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, unknown30) == 0x30);
STATIC_ASSERT(offsetof(GunpowderBarrelState, radiusGrowthPerFrame) == 0x34);
STATIC_ASSERT(offsetof(GunpowderBarrelState, accumulatedFallVelocity) == 0x38);
STATIC_ASSERT(offsetof(GunpowderBarrelState, unknown3C) == 0x3C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, unknown3E) == 0x3E);
STATIC_ASSERT(offsetof(GunpowderBarrelState, pad3F) == 0x3F);
STATIC_ASSERT(offsetof(GunpowderBarrelState, unknown40) == 0x40);
STATIC_ASSERT(offsetof(GunpowderBarrelState, homingHeadingA) == 0x44);
STATIC_ASSERT(offsetof(GunpowderBarrelState, homingHeadingB) == 0x46);
STATIC_ASSERT(offsetof(GunpowderBarrelState, configFlags) == 0x48);
STATIC_ASSERT(offsetof(GunpowderBarrelState, motionFlags) == 0x49);
STATIC_ASSERT(offsetof(GunpowderBarrelState, heldFlagsRaw) == 0x4A);
STATIC_ASSERT(offsetof(GunpowderBarrelState, heldFlags) == 0x4A);
STATIC_ASSERT(offsetof(GunpowderBarrelState, pad4B) == 0x4B);
STATIC_ASSERT(offsetof(GunpowderBarrelState, launchYaw) == 0x50);
STATIC_ASSERT(offsetof(GunpowderBarrelState, pad52) == 0x52);
STATIC_ASSERT(offsetof(GunpowderBarrelState, impactSoundCooldown) == 0x54);
STATIC_ASSERT(sizeof(GunpowderBarrelState) == 0x58);

int gunpowderBarrel_isHeld(GameObject* obj);
int gunpowderBarrel_canBeGrabbed(GameObject* obj);
void gunpowderBarrel_clearHeldState(GameObject* obj);
void gunpowderBarrel_setHeldState(GameObject* obj);
void gunpowderBarrel_launchAtTarget(GameObject* obj, u8 usePlayerStrength);
void gunpowderBarrel_setPlayerHeldState(GameObject* obj, u8 heldByPlayer);
void gunpowderBarrel_addThrowVelocity(GameObject* obj, f32* velocity);
void gunpowderBarrel_homeOnTarget(GameObject* obj, s16 rotYMode, s16 rotZMode);
void gunpowderBarrel_triggerExplosion(GameObject* obj);
void gunpowderBarrel_updatePhysics(GameObject* obj);
int gunpowderBarrel_getExtraSize(void);
void gunpowderBarrel_free(GameObject* obj, int keepLinkedTimer);
void gunpowderBarrel_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void gunpowderBarrel_hitDetect(GameObject* barrel);
void gunpowderBarrel_update(GameObject* obj);
void gunpowderBarrel_init(GameObject* obj, GunpowderBarrelPlacement* placement);

extern f32 gGunpowderBarrelReleaseOffset;
extern f32 gGunpowderBarrelImpactSoundSpeedThreshold;
extern f32 gGunpowderBarrelFallDetonationThreshold;
extern ObjectDescriptor11WithPadding gGunpowderBarrelObjDescriptor;

#endif /* DLLS_OBJECTS_344_H_ */
