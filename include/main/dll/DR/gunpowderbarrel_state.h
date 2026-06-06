#ifndef MAIN_DLL_DR_GUNPOWDERBARREL_STATE_H_
#define MAIN_DLL_DR_GUNPOWDERBARREL_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* Per-object extra state for the gunpowder barrel (carryable). */
typedef struct GunpowderBarrelState {
    u8 pad00[7];
    u8 unk07;
    u8 pad08[4];
    int unk0C;
    int linkedObj;  /* 0x10 */
    u8 pad14;
    u8 unk15;       /* blocks scaling/grabbing while set */
    u8 unk16;
    u8 unk17;       /* blocks scaling while set */
    f32 unk18;      /* must be zero to grab */
    u8 pad1C[4];
    f32 velX;       /* launch/throw velocity */
    f32 velY;
    f32 velZ;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    f32 unk38;
    s16 unk3C;
    u8 unk3E;
    u8 pad3F;
    int unk40;
    s16 unk44;
    s16 unk46;
    u8 flags48;     /* 0x40 = save position at the linked barrel */
    u8 flags49;     /* 1 sleeping, 2 in flight */
    u8 heldFlags;   /* GpbHeldByte: held / playerHeld bits */
    u8 pad4B[5];
    s16 launchYaw;  /* 0x50 */
    u8 pad52[2];
    f32 unk54;
} GunpowderBarrelState;
STATIC_ASSERT(offsetof(GunpowderBarrelState, launchYaw) == 0x50);
STATIC_ASSERT(sizeof(GunpowderBarrelState) == 0x58);

#endif
