#ifndef MAIN_DLL_ARW_ARWING_STATE_H_
#define MAIN_DLL_ARW_ARWING_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* Per-object extra state for the playable Arwing
 * (arwarwing_getExtraSize == 0x498). */
typedef struct ArwingState {
    int unk00;
    int escortObj;       /* 0x004: def 0x606 link */
    int gunObjL;         /* 0x008: def 0x610 */
    int gunObjR;         /* 0x00c: def 0x615 */
    int bombObj;         /* 0x010: def 0x611 */
    f32 homeX;           /* 0x014: spawn position */
    f32 homeY;
    f32 homeZ;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    f32 camPos[3];       /* 0x02c: pushed to the camera each update */
    f32 unk38;
    f32 unk3C;
    f32 unk40;
    f32 unk44;
    f32 velX;            /* 0x048 */
    f32 velY;
    f32 velZ;
    f32 unk54;
    f32 unk58;
    f32 unk5C;
    f32 unk60;
    f32 unk64;
    f32 unk68;
    f32 unk6C;
    u8 pad70[8];
    f32 unk78;
    u8 pad7C[8];
    f32 unk84;
    f32 unk88;
    f32 unk8C;
    f32 unk90;
    f32 unk94;
    f32 unk98;
    f32 rollEnergy;      /* 0x09c */
    f32 rollEnergyMax;   /* 0x0a0 */
    f32 unkA4;
    f32 unkA8;
    f32 wingFlexCur;     /* 0x0ac */
    f32 wingFlexTarget;  /* 0x0b0 */
    f32 rollCooldown;    /* 0x0b4 */
    f32 rollCooldownInit;/* 0x0b8 */
    f32 rollRegenDelay;  /* 0x0bc */
    u8 pathBlock[0x268]; /* 0x0c0: gPathControlInterface block */
    f32 damageFlashTimer;/* 0x328 */
    f32 knockVelX;       /* 0x32c */
    f32 knockVelZ;       /* 0x330 */
    u8 pad334[4];
    u8 hitShake;         /* 0x338: damage camera-shake active */
    u8 flags339;         /* 0x339: 0x80 damage flash; Arw339Flags overlay */
    s16 shakeYaw;        /* 0x33a */
    s16 shakePitch;      /* 0x33c */
    u8 pad33E[2];
    int unk340;
    int unk344;
    f32 unk348;
    f32 unk34C;
    int unk350;
    int unk354;
    int rollInput;       /* 0x358 */
    f32 unk35C;
    f32 unk360;
    int unk364;
    int unk368;
    int pitchAccum;      /* 0x36c */
    f32 unk370;
    f32 unk374;
    f32 unk378;
    int unk37C;
    int unk380;
    f32 unk384;
    f32 unk388;
    f32 unk38C;
    f32 unk390;
    f32 unk394;
    int unk398;
    f32 unk39C;
    f32 unk3A0;
    f32 unk3A4;
    f32 unk3A8;
    f32 unk3AC;
    f32 unk3B0;
    f32 unk3B4;
    f32 unk3B8;
    f32 unk3BC;
    u16 unk3C0;
    u8 pad3C2[2];
    f32 unk3C4;
    f32 unk3C8;
    u16 unk3CC;
    u8 pad3CE[2];
    f32 unk3D0;
    f32 unk3D4;
    u16 unk3D8;
    u8 pad3DA[2];
    f32 unk3DC;
    f32 unk3E0;
    f32 unk3E4;
    f32 unk3E8;
    f32 unk3EC;
    f32 unk3F0;
    u16 inputFlags;      /* 0x3f4: 0x100 fire, 0x400 roll-R, 0x800 roll-L */
    u16 inputFlagsPrev;  /* 0x3f6 */
    u16 inputFlags2;     /* 0x3f8: 0x100 fire held */
    u8 unk3FA;
    u8 pad3FB[9];
    u8 laserLevel;       /* 0x404: 0 single, 1 twin, 2 hyper */
    u8 laserSide;        /* 0x405: alternating muzzle */
    u8 pad406[2];
    f32 fireCooldown;    /* 0x408 */
    u16 fireDelay;       /* 0x40c: frames loaded into fireCooldown */
    u16 projLifetime;    /* 0x40e */
    f32 projSpeed;       /* 0x410 */
    f32 fireTimer;       /* 0x414 */
    int thrusterL;       /* 0x418: def 0x6de exhaust objects */
    int thrusterR;       /* 0x41c */
    u8 pad420[0x18];
    int unk438;
    u8 unk43C;
    u8 bombSide;         /* 0x43d */
    u8 pad43E[2];
    f32 unk440;
    s16 unk444;
    s16 unk446;
    f32 unk448;
    u8 bombCount;        /* 0x44c */
    u8 maxBombCount;     /* 0x44d */
    u16 unk44E;          /* engine pitch fed to fn_8022F270 */
    void *light;         /* 0x450 */
    int wingVec[4];      /* 0x454: objModelGetVecFn slots 0-3 */
    f32 wingFlexScale;   /* 0x464 */
    u8 shield;           /* 0x468 */
    u8 maxShield;        /* 0x469 */
    u8 pad46A[2];
    f32 modeTimer;       /* 0x46c */
    u8 collectedRings;   /* 0x470 */
    u8 requiredRings;    /* 0x471 */
    u8 counter472;
    u8 counter473;
    u8 counter474;
    u8 counter475;
    u8 counter476;
    u8 flags477;         /* 1 initialized, 2 roll-left, 4 roll-right */
    u8 mode;             /* 0x478: 4 dead, 5 exploding, 6 warp-out */
    u8 pad479[2];
    u8 levelIndex;       /* 0x47b */
    u16 score;           /* 0x47c */
    u8 scoreSlot;        /* 0x47e */
    u8 aimSnapshotValid; /* 0x47f */
    u8 fullLoadout;      /* 0x480 */
    u8 pad481[3];
    f32 aimOffsetX;      /* 0x484: camera-relative aim snapshot */
    f32 aimOffsetY;
    f32 aimOffsetZ;
    s16 aimYaw;          /* 0x490 */
    s16 aimPitch;        /* 0x492 */
    s16 aimRoll;         /* 0x494 */
    u8 pad496[2];
} ArwingState;
STATIC_ASSERT(sizeof(ArwingState) == 0x498);
STATIC_ASSERT(offsetof(ArwingState, inputFlags) == 0x3f4);
STATIC_ASSERT(offsetof(ArwingState, light) == 0x450);

#endif
