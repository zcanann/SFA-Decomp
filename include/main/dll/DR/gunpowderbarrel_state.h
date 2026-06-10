#ifndef MAIN_DLL_DR_GUNPOWDERBARREL_STATE_H_
#define MAIN_DLL_DR_GUNPOWDERBARREL_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* Per-object extra state for the gunpowder barrel (carryable). */
typedef struct GunpowderBarrelState {
    u8 pad00[7];
    u8 unk07;
    u8 pad08[4];
    int queuedHitObject;
    int linkedTimerObject;  /* 0x10 */
    u8 pad14;
    u8 heldByCarryInterface;
    u8 unk16;
    u8 fuseFrames;
    f32 respawnTimer;
    f32 releaseTimer;
    f32 throwVelX;
    f32 throwVelY;
    f32 throwVelZ;
    f32 hitRadius;
    f32 unk30;
    f32 radiusGrowthPerFrame;
    f32 unk38;
    s16 unk3C;
    u8 unk3E;
    u8 pad3F;
    int unk40;
    s16 unk44;
    s16 unk46;
    u8 configFlags; /* 0x40 = save position at the linked barrel */
    u8 motionFlags; /* 1 sleeping, 2 in flight */
    u8 heldFlags;   /* GpbHeldByte: held / playerHeld bits */
    u8 pad4B[5];
    s16 launchYaw;  /* 0x50 */
    u8 pad52[2];
    f32 impactSoundCooldown;
} GunpowderBarrelState;
STATIC_ASSERT(offsetof(GunpowderBarrelState, queuedHitObject) == 0x0C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, linkedTimerObject) == 0x10);
STATIC_ASSERT(offsetof(GunpowderBarrelState, respawnTimer) == 0x18);
STATIC_ASSERT(offsetof(GunpowderBarrelState, releaseTimer) == 0x1C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, throwVelX) == 0x20);
STATIC_ASSERT(offsetof(GunpowderBarrelState, hitRadius) == 0x2C);
STATIC_ASSERT(offsetof(GunpowderBarrelState, configFlags) == 0x48);
STATIC_ASSERT(offsetof(GunpowderBarrelState, launchYaw) == 0x50);
STATIC_ASSERT(sizeof(GunpowderBarrelState) == 0x58);

#endif
