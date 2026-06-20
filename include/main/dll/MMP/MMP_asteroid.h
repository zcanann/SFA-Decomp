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
    int unk10;
    int unk14;
    int unk18;
    int unk1C;
    int unk20;
    int unk24;
    int unk28;
    int unk2C;
    int unk30;
    int unk34;
    int unk38;
    int unk3C;
    f32 offsetX;
    f32 offsetY;
    f32 offsetZ;
    s8 gameBitValue;
    s8 unk4D;
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
    f32 unk68;
    f32 unk6C;
    f32 unk70;
    u8 unk74[0x261 - 0x74];
    s8 unk261;
    u8 unk262[0x26C - 0x262];
    f32 unk26C;
    f32 unk270;
    f32 unk274;
    f32 unk278;
    f32 unk27C;
    f32 unk280;
    f32 unk284;
    f32 unk288;
    f32 unk28C;
    f32 unk290;
    f32 unk294;
    f32 unk298;
    s16 unk29C;
    u8 unk29E[0x2A0 - 0x29E];
} DimBossIceSmashState;

STATIC_ASSERT(sizeof(DimBossIceSmashState) == 0x2A0);

#endif /* MAIN_DLL_MMP_MMP_ASTEROID_H_ */
