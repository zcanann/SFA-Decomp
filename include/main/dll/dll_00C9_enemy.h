#ifndef MAIN_DLL_DLL_00C9_ENEMY_H_
#define MAIN_DLL_DLL_00C9_ENEMY_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "global.h"
#include "main/objanim_update.h"

/* obj+0xB8 extra record for the generic enemy family. */
typedef struct EnemyState {
    u8 unk0[0x4 - 0x0];
    u32 flags;
    u8 unk8[0x29C - 0x8];
    GameObject* trackedObj;
    u8 unk2A0[0x2A8 - 0x2A0];
    f32 aggroRange; /* engagement range derived from placement data */
    f32 sightRange; /* patrol/detection range used by curve setup */
    s16 current;    /* numerator used by enemy_getHealthFraction */
    u16 max;        /* spawn-time denominator */
    s16 unk2B4;
    s16 unk2B6;
    u8 unk2B8[0x2D8 - 0x2B8];
    f32 freezeRecoverTimer;
    u32 controlFlags;
    int initialFlags;
    u32 flags2E4;
    int flags2E8;
    s16 unk2EC;
    u8 unk2EE[0x2F2 - 0x2EE];
    u8 curveIndex;
    u8 curveParamA;
    u8 curveParamB;
    u8 unk2F5[0x2F8 - 0x2F5];
    s16 unk2F8;
    u8 unk2FA[0x2FC - 0x2FA];
    f32 health;
    f32 animDeltaScale;
    f32 unk304;
    f32 unk308;
    f32 particleScale;
    f32 unk310;
    u8 unk314[0x324 - 0x314];
    f32 unk324;
    f32 unk328;
    f32 unk32C;
    f32 unk330;
    f32 intervalTimer;
    s16 phaseAngle;
    u8 unk33A[0x340 - 0x33A];
    int lastHitObject;
    u8 unk344[0x368 - 0x344];
    int modelLight;
    int tailSimHandle;
    u8 unk370[0x374 - 0x370];
} EnemyState;

STATIC_ASSERT(offsetof(EnemyState, aggroRange) == 0x2A8);

void objAnimFn_8014a9f0(short* obj, int state);
void FUN_8014ab58(u64 param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                  double param_7, u64 param_8, u16* param_9, int* param_10, u32 param_11, u32 param_12, u32 param_13,
                  u32 param_14, u32 param_15, u32 param_16);
void FUN_8014c0b4(double param_1, double param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9, int param_10);
void FUN_8014c528(u16* param_1, int param_2);
void FUN_8014c690(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, u32 param_9, u32 param_10, int param_11);
void FUN_8014c694(u64 param_1, u64 param_2, u64 param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                  u64 param_8, int param_9);
void FUN_8014c78c(u32 param_1, u32 param_2, int param_3, int* param_4);
int enemy_SeqFn(int* node, int unused, ObjAnimUpdateState* animUpdate);
void fn_8014C66C(GameObject* obj, GameObject* target);
void fn_8014C5C0(GameObject* obj);
void fn_8014C63C(GameObject* obj);
u8 fn_8014C4D8(GameObject* obj);
void fn_8014C540(GameObject* obj, int* outIdx, f32* outA, f32* outB);
f32 enemy_getHealthFraction(GameObject* obj);
f32 sidekickToy_accelerateTowardTarget3D(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
f32 sidekickToy_accelerateTowardTargetXZ(GameObject* obj, f32 tx, f32 ty, f32 tz, f32 accel, f32 speedScale,
                                         f32 maxVel, f32 drag);
int enemy_getExtraSize(void);
int enemy_getObjectTypeId(void);
void enemy_release(void);
void enemy_initialise(void);
void enemy_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void enemy_hitDetect(GameObject* obj);
void enemy_free(GameObject* obj, int flag);
void enemy_update(int obj);
void enemy_init(GameObject* obj, u8* setup, int flag);
u32 FUN_8014ca90(int param_1);
void FUN_8014caf4(int param_1, u32* param_2, float* param_3, float* param_4);
void FUN_8014cbbc(int param_1);
double FUN_8014cbcc(int param_1);
void FUN_8014cc7c(int param_1);
void FUN_8014ccac(int param_1, u32 param_2);
void FUN_8014ccb8(double param_1, double param_2, double param_3, int param_4, int param_5, float* param_6,
                  char param_7);
double FUN_8014cfac(double param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                    double param_7, int param_8);
double FUN_8014d2a4(double param_1, double param_2, double param_3, double param_4, double param_5, double param_6,
                    double param_7, int param_8);

#endif /* MAIN_DLL_DLL_00C9_ENEMY_H_ */
