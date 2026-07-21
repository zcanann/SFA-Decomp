#ifndef MAIN_DLL_MMPTRENCHFXSTATE_STRUCT_H_
#define MAIN_DLL_MMPTRENCHFXSTATE_STRUCT_H_

#include "types.h"
#include "main/dll/partfx_interface.h"
#include "main/obj_placement.h"

/*
 * MmpTrenchfxPlacement - the placement/setup record passed to
 * mmp_trenchfx_init. Common ObjPlacement head (position / mapId) then
 * the trench emitter's class-specific setup fields, matching the
 * <Family>Placement convention used by the other object DLLs.
 */
typedef struct MmpTrenchFxPlacement
{
    ObjPlacement base;  /* 0x00: common placement head */
    u8 pad18[1];        /* 0x18 */
    s8 emitAngleZ;      /* 0x19: roll preset (<<8), seeds anim.rotZ */
    s8 emitAngleY;      /* 0x1A: pitch preset (<<8), seeds anim.rotY */
    s8 emitAngleX;      /* 0x1B: yaw preset (<<8), seeds anim.rotX */
    u8 extentX;         /* 0x1C: random offset half-extent X (<<2) */
    u8 extentZ;         /* 0x1D: random offset half-extent Z (<<2) */
    u8 extentY;         /* 0x1E: random offset half-extent Y (<<2) */
    u8 pad1F[5];        /* 0x1F */
    s16 enableBit;      /* 0x24: gamebit gate, -1 = always on */
} MmpTrenchFxPlacement;

STATIC_ASSERT(offsetof(MmpTrenchFxPlacement, emitAngleZ) == 0x19);
STATIC_ASSERT(offsetof(MmpTrenchFxPlacement, extentX) == 0x1c);
STATIC_ASSERT(offsetof(MmpTrenchFxPlacement, enableBit) == 0x24);
STATIC_ASSERT(sizeof(MmpTrenchFxPlacement) == 0x28);

typedef struct MmpTrenchFxState
{
    s16 enableBit; /* data+0x24 gamebit gate, -1 = always on */
    u16 extentX; /* data[0x1C..0x1E] << 2 random offset half-extents */
    u16 extentZ;
    u16 extentY;
    s16 emitAngles[3]; /* roll/pitch/yaw presets, mirrored to obj+4/2/0 */
    u8 reserved0E[2];
    PartFxSpawnParams effect;
    f32 emitCooldown; /* rand(100,200) frames between bursts */
    f32 emitTimer; /* rand(50,100); spawns effect 0x71F while > 0 */
} MmpTrenchFxState;

STATIC_ASSERT(offsetof(MmpTrenchFxState, emitAngles) == 0x8);
STATIC_ASSERT(offsetof(MmpTrenchFxState, effect) == 0x10);
STATIC_ASSERT(offsetof(MmpTrenchFxState, emitCooldown) == 0x28);
STATIC_ASSERT(offsetof(MmpTrenchFxState, emitTimer) == 0x2c);
STATIC_ASSERT(sizeof(MmpTrenchFxState) == 0x30);

#endif
