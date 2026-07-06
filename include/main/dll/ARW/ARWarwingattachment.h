#ifndef MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_
#define MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gPressureSwitchObjDescriptor;
extern ObjectDescriptor gWM_LaserTargetObjDescriptor;

void LaserBeam_update(int param_1);
void FUN_801f0cb8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801f0cf0(int param_1);
void FUN_801f0d8c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801f0d90(int param_1);
void FUN_801f0de8(u32 param_1);
void FUN_801f0dec(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801f10ac(void);
void FUN_801f10d8(void);
void FUN_801f10dc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801f1104(void);
void FUN_801f15ac(u16 *param_1,int param_2);
void FUN_801f15b0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState);
void FUN_801f1634(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_801f1934(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801f195c(int param_1);
void FUN_801f1a64(int param_1,int param_2);
void FUN_801f1ac0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801f1d3c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_801f23c0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32 FUN_801f25b4(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
u32 FUN_801f26a8(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801f284c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801f28d4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_801f28d8(u16 *param_1,u16 *param_2);
void FUN_801f28dc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801f2904(u32 param_1);
void FUN_801f2ac8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801f2b94(short *param_1);

int PressureSwitch_getExtraSize(void);
int PressureSwitch_getObjectTypeId(void);
int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void PressureSwitch_free(void);
void PressureSwitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void PressureSwitch_hitDetect(void);
void PressureSwitch_update(int obj);
void PressureSwitch_init(int *obj, u8 *init);
void PressureSwitch_release(void);
void PressureSwitch_initialise(void);

int WM_LaserTarget_getExtraSize(void);
int WM_LaserTarget_getObjectTypeId(void);
int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate, int arg3);
void WM_LaserTarget_free(void);
void WM_LaserTarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_LaserTarget_hitDetect(void);
void WM_LaserTarget_update(int *obj);
void WM_LaserTarget_init(char *obj, s8 *p);
void WM_LaserTarget_release(void);
void WM_LaserTarget_initialise(void);
int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void lightsource_render(void *obj, int p1, int p2, int p3, int p4, s8 visible);

#endif /* MAIN_DLL_ARW_ARWARWINGATTACHMENT_H_ */
