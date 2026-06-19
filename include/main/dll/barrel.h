#ifndef MAIN_DLL_BARREL_H_
#define MAIN_DLL_BARREL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

int grimble_stateHandlerA00(int obj, char *state, f32 arg);
int grimble_stateHandlerA01(int obj, char *state, f32 arg);
int grimble_stateHandlerA02(int obj, char *state, f32 arg);
u32
FUN_801620c0(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
bool FUN_8016228c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32
FUN_80162450(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,short *param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_801628c4(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_80162b78(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_80162ec0(short *param_1);
void cannonclaw_release(void);
void FUN_80163220(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80163308(int param_1);

extern ObjectDescriptor gGrimbleObjDescriptor;
extern ObjectDescriptor gCannonClawObjDescriptor;

int grimble_getExtraSize(void);
int grimble_getObjectTypeId(void);
void grimble_free(int obj);
void grimble_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void grimble_hitDetect(int obj);
void grimble_update(int obj);
void grimble_init(int obj, int p2, int p3);
void grimble_release(void);
void grimble_initialise(void);

int cannonclaw_getExtraSize(void);
int cannonclaw_getObjectTypeId(void);
void cannonclaw_free(void);
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void cannonclaw_hitDetect(void);
void cannonclaw_update(u8* obj);
void cannonclaw_init(s16* dst, void* src);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_BARREL_H_ */
