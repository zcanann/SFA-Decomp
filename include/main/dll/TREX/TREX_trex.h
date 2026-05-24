#ifndef MAIN_DLL_TREX_TREX_TREX_H_
#define MAIN_DLL_TREX_TREX_TREX_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor24 gShopObjDescriptor;

#define SB_FIREBALL_SPIN_STEP -800
#define SB_FIREBALL_TRAIL_PARTICLE_ID 169
#define SB_FIREBALL_SETUP_SIZE 4
#define SB_FIREBALL_SETUP_MODEL_ID 389
#define SB_FIREBALL_SETUP_PARAM 5
#define SB_FIREBALL_HITBOX_ENABLE_DELAY 15
#define SB_FIREBALL_HITBOX_TYPE 5
#define SB_FIREBALL_HITBOX_PRIORITY 1
#define SB_FIREBALL_HITBOX_SIZE 16
#define SB_FIREBALL_SOLID_HITBOX_FLAG 1

void FUN_801e42f8(int param_1);
void FUN_801e4350(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801e4378(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_801e451c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801e481c(uint param_1);
void FUN_801e48f4(void);
void FUN_801e4928(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801e4950(int param_1);
void FUN_801e4a14(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9);
void FUN_801e4c58(int param_1);
void FUN_801e4cb0(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801e4cd8(uint param_1);
void FUN_801e4d6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9);
void FUN_801e50a4(int param_1);
undefined4 FUN_801e514c(uint param_1,undefined4 param_2,int param_3);
void FUN_801e521c(int param_1);
void FUN_801e524c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801e55c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10);
void FUN_801e55c4(uint param_1);
void FUN_801e5684(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801e56ac(int param_1);
void FUN_801e5734(undefined4 param_1);
void FUN_801e5790(void);
void FUN_801e57e0(short *param_1);
void FUN_801e59ec(uint param_1);
void FUN_801e5afc(int param_1);
void FUN_801e5b80(int param_1);
void FUN_801e5bd4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_801e5dd0(int param_1,int param_2);
void FUN_801e5f78(int param_1);
void FUN_801e5fc4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
undefined4 FUN_801e5fec(int param_1,undefined4 param_2,int param_3);
void FUN_801e60cc(uint param_1);
void FUN_801e62b8(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_801e62e0(int param_1);
void FUN_801e63f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_801e64c4(void);
void FUN_801e6510(uint param_1);
void FUN_801e6558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void shop_initialise(void);
void shop_release(void);
void shop_init(int obj,int objDef);
void shop_update(int obj);
void shop_hitDetect(void);
void shop_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void shop_free(int* obj);
int shop_func08(void);
int shop_getExtraSize(void);
s32 shop_setScale(int *obj);
void shop_func0B(int* obj, int v, int p3);
void shop_func15(int* obj, int v);
void shop_func16(int* obj, int p2, int p3);
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4);

#endif /* MAIN_DLL_TREX_TREX_TREX_H_ */
