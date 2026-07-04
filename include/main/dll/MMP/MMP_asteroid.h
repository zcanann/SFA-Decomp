#ifndef MAIN_DLL_MMP_MMP_ASTEROID_H_
#define MAIN_DLL_MMP_MMP_ASTEROID_H_

#include "ghidra_import.h"
#include "global.h"

void xyzanimator_update(int obj);
void FUN_801950ac(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801950d4(u32 param_1,u32 param_2,u32 *param_3);
void FUN_801954f0(void);
void FUN_801954f4(int param_1);
void FUN_801955a4(int param_1);
void FUN_801955c8(int param_1);
void FUN_80195704(int param_1,int param_2);
void FUN_8019575c(u16 *param_1,int param_2,int param_3);
void FUN_80195b40(int obj);
void FUN_80195b74(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80195b9c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_80196244(u16 *param_1,int param_2);
void FUN_8019635c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80196384(int param_1);
void texframeanimator_update(int *obj);
void texframeanimator_init(int *obj, u8 *params);


/* xyzanimator per-object extra state (xyzanimator_getExtraSize == 0x50):
 * 16 int slots, current-offset vec at 0x40, mode/active bytes, looped SFX id. */
typedef struct XyzAnimatorState {
    int rowCount;
    int unk4;
    int unk8;
    int dataBuffer;
    int posABuffer; /* s16 stream: per-block posA coord */
    int posBBuffer; /* s16 stream: per-block posB coord */
    int unk18;
    int unk1C;
    int unk20;
    int unk24;
    int edgeV0xBuffer; /* s16 stream: edge endpoint v0x */
    int edgeV1xBuffer; /* s16 stream: edge endpoint v1x */
    int edgeV0yBuffer; /* s16 stream: edge endpoint v0y */
    int edgeV1yBuffer; /* s16 stream: edge endpoint v1y */
    int edgeV0zBuffer; /* s16 stream: edge endpoint v0z */
    int edgeV1zBuffer; /* s16 stream: edge endpoint v1z */
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    s8 gameBitValue;
    s8 loopCount; /* 0x4D: animation-pass counter; > 2 stops/wraps the update */
    u16 loopSfxId;
} XyzAnimatorState;

STATIC_ASSERT(sizeof(XyzAnimatorState) == 0x50);

/* xyzanimator placement/def data (obj+0x4C). Extent past 0x34 unknown;
 * 0x18.. matches the common animator-def header position. */
typedef struct XyzAnimatorPlacement {
    u8 unk0[0x18 - 0x0];
    s16 triggerGameBit;
    s16 doneGameBit;
    s16 startX;
    s16 startY;
    s16 startZ;
    s16 targetX;
    s16 targetY;
    s16 targetZ;
    s8 blockLayer;
    s8 speedX;
    s8 speedY;
    s8 speedZ;
    u8 mode;
    u8 unk2D[0x34 - 0x2D];
} XyzAnimatorPlacement;


/* dimbossicesmash per-object extra state (dimbossicesmash_getExtraSize
 * == 0x2A0): smash vectors at 0x26C.., home/target vec 0x278, s16 timer
 * at 0x29C. 0x0-0x68 region untyped (only float trio observed). */
typedef struct DimBossIceSmashState {
    u8 unk0[0x68 - 0x0];
    f32 homingDirX;     /* 0x68: surface/contact normal used by homing reflect */
    f32 homingDirY;
    f32 homingDirZ;
    u8 unk74[0x261 - 0x74];
    s8 homingEnabled;   /* 0x261: gate for the homing-reflection velocity block */
    u8 unk262[0x26C - 0x262];
    f32 spawnScaleX;    /* 0x26C: spawn offset scaled by rootMotionScale */
    f32 spawnScaleY;
    f32 spawnScaleZ;
    f32 angVelX;        /* 0x278: angular velocity (integrated into rot) */
    f32 angVelY;
    f32 angVelZ;
    f32 angAccelX;      /* 0x284: angular acceleration (integrates angVel) */
    f32 angAccelY;
    f32 angAccelZ;
    f32 accelX;         /* 0x290: linear acceleration (integrates velocity) */
    f32 accelY;
    f32 accelZ;
    s16 timer;          /* 0x29C: frame timer vs placement lifetime */
    u8 unk29E[0x2A0 - 0x29E];
} DimBossIceSmashState;

STATIC_ASSERT(sizeof(DimBossIceSmashState) == 0x2A0);

#endif /* MAIN_DLL_MMP_MMP_ASTEROID_H_ */
