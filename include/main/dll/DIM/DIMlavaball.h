#ifndef MAIN_DLL_DIM_DIMLAVABALL_H_
#define MAIN_DLL_DIM_DIMLAVABALL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gMMP_levelcontrolObjDescriptor;
extern ObjectDescriptor gMoonSeedBushObjDescriptor;
extern ObjectDescriptor gMMP_asteroid_reObjDescriptor;
extern ObjectDescriptor gMMP_moonrockObjDescriptor;
extern ObjectDescriptor gMMP_trenchFXObjDescriptor;
extern ObjectDescriptor gMMP_gyserventObjDescriptor;

void MMP_levelcontrol_update(int obj);
u32
FUN_801a68b8(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10
            ,ObjAnimUpdateState *animUpdate,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_801a6ab0(void);
void FUN_801a6ae8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a6b10(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801a7648(int param_1);
void FUN_801a764c(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801a777c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a77a4(int param_1);
void FUN_801a7870(short *param_1,int param_2);
u32
FUN_801a7874(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,
            u32 param_10,ObjAnimUpdateState *animUpdate);
void FUN_801a7a6c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a7a94(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801a8164(int param_1);
int FUN_801a8168(u64 param_1,double param_2,double param_3,double param_4,u32 param_5,
                float *param_6,u32 *param_7);
void FUN_801a8284(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9);
void FUN_801a8454(int param_1);
void FUN_801a86b0(int param_1);
void FUN_801a8748(u32 param_1,u32 param_2,u32 param_3);
void FUN_801a8ae8(double param_1,double param_2,double param_3,int param_4);
void FUN_801a8b20(int param_1,char param_2);
void FUN_801a8b64(int param_1);
void FUN_801a8bb0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801a8c14(void);
void FUN_801a8c18(int param_1,int param_2);
void FUN_801a8d70(int obj);

void MMP_levelcontrol_release(void);
void MMP_levelcontrol_initialise(void);

int MoonSeedBush_getExtraSize(void);
int MoonSeedBush_getObjectTypeId(void);
int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void MoonSeedBush_free(void);
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MoonSeedBush_hitDetect(void);
void MoonSeedBush_update(int obj);
void MoonSeedBush_init(int obj, int data);
void MoonSeedBush_release(void);
void MoonSeedBush_initialise(void);

int mmp_asteroid_re_getExtraSize(void);
int mmp_asteroid_re_getObjectTypeId(void);
int fn_801A6F4C(int obj, int unused, ObjAnimUpdateState *animUpdate);
void mmp_asteroid_re_free(void);
void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void mmp_asteroid_re_hitDetect(void);
void mmp_asteroid_re_update(int obj);
void mmp_asteroid_re_init(int obj);
void mmp_asteroid_re_release(void);
void mmp_asteroid_re_initialise(void);

int mmp_moonrock_getExtraSize(void);
int mmp_moonrock_getObjectTypeId(void);
void mmp_moonrock_free(int obj);
void mmp_moonrock_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void mmp_moonrock_hitDetect(void);
void mmp_moonrock_update(int obj);
void mmp_moonrock_init(int obj, int param2);
void mmp_moonrock_release(void);
void mmp_moonrock_initialise(void);

int mmp_trenchfx_getExtraSize(void);
int mmp_trenchfx_getObjectTypeId(void);
void mmp_trenchfx_free(int obj);
void mmp_trenchfx_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void mmp_trenchfx_hitDetect(void);
void mmp_trenchfx_update(int obj);
void mmp_trenchfx_init(int obj, int data);
void mmp_trenchfx_release(void);
void mmp_trenchfx_initialise(void);

int mmp_gyservent_getExtraSize(void);
int mmp_gyservent_getObjectTypeId(void);
void mmp_gyservent_free(void);
void mmp_gyservent_render(void);
void mmp_gyservent_hitDetect(void);
void mmp_gyservent_update(int obj);
void mmp_gyservent_init(int obj);
void mmp_gyservent_release(void);
void mmp_gyservent_initialise(void);

#endif /* MAIN_DLL_DIM_DIMLAVABALL_H_ */
