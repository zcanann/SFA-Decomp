#ifndef MAIN_DLL_CF_CFBABY_H_
#define MAIN_DLL_CF_CFBABY_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gLanternFireFlyObjDescriptor;
extern ObjectDescriptor gFireFlyLanternObjDescriptor;
extern ObjectDescriptor gFlammableVineObjDescriptor;

void FireFlyLantern_init(int param_1,int param_2);
int FireFlyLantern_spawnFireFly(int *obj);
int FireFlyLantern_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int FUN_80187664(u64 param_1,double param_2,double param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
int FUN_801877b0(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FUN_801878f8(int param_1);
void FUN_8018793c(int param_1);
void FUN_8018795c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_80187b14(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80187b18(int param_1);
void FUN_80187b3c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_80187b64(int param_1);
void FUN_80187bf4(u32 param_1);
void FUN_80187ee0(u16 *param_1,int param_2);
void FUN_80188038(void);
void FUN_8018806c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801880e0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801883bc(short *param_1,int param_2);
void infopoint_hitDetect(void);
void FUN_80188470(u32 param_1);
void FUN_80188668(u16 *param_1,int param_2);
void FUN_8018866c(int param_1);
void FUN_801887d8(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_80188800(int param_1);
void FUN_80188864(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80188868(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
void FUN_80188890(short *param_1);
void FUN_80188a8c(float *param_1,float *param_2,float *param_3);
void FUN_80188b14(short *param_1,int param_2);
void FUN_80188d34(void);
void FUN_80188f94(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_80189028(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);
u32
FUN_80189054(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10,
            ObjAnimUpdateState *animUpdate,int param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_80189a90(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_80189e94(int param_1,int param_2);
int Landed_Arwing_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

int flammablevine_getExtraSize(void);
int flammablevine_getObjectTypeId(void);
void flammablevine_free(int obj);
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void flammablevine_hitDetect(int obj);
void flammablevine_update(int obj);
void flammablevine_init(int obj, int def);
void flammablevine_release(void);
void flammablevine_initialise(void);

#endif /* MAIN_DLL_CF_CFBABY_H_ */
