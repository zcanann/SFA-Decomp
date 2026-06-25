#ifndef MAIN_DLL_COLLECTABLE_H_
#define MAIN_DLL_COLLECTABLE_H_

#include "ghidra_import.h"
#include "main/dll/tricky_state.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor20WithPadding gTrickyObjDescriptor;

u8 *Tricky_findNearestGroup4BObject(u8 *obj, TrickyState *state);
int FUN_80145120(int param_1,int param_2);
void FUN_80145230(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int *param_10,int param_11,u32 param_12,u8 param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_801455e8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801457a4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void trickyFn_801451d8(int obj,int state);
void trickyFn_80144f50(int obj,int state);
void FUN_80145ea4(int param_1);
void FUN_80145ee8(int param_1,int param_2,int param_3);
int Tricky_func10(int *obj,int targetObj);
void Tricky_func0F(int *obj,int commandEnabled,int targetObj);
void sideCommandEnable(int obj,int targetObj,int commandKind,int commandType);
int Tricky_updateSideCommandPrompts(int obj);
u32 FUN_80146874(void);
void Tricky_destroy(int obj,int shouldKeepFlameChildren);
void Tricky_init(int obj);
int tricky_SeqFn(int obj,int unused,ObjAnimUpdateState *animUpdate);
void Tricky_update(int obj);
void fn_80148C18(int obj,int state);
void tricky_handleDefeat(int obj,int state);
int collectibleFn_80149cec(int obj,int state,int spawnBits,u32 useAltMode,u32 mode);
u8 baddieTargetFn_8014a150(int obj,int state,void *from,void *to);
void baddieFn_8014a304(int obj,int state,float radius);
void fn_8014A5FC(int obj,int state);
void fn_8014A86C(int obj,int state,float *nearestFloorY,float *nearestSpecialY);
void Tricky_render(int obj,int param_2,int param_3,int param_4,int param_5,char doRender);
void Tricky_hitDetect(int obj);
void FUN_80146f94(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80146f98(int param_1);
void FUN_80146f9c(void);
void FUN_80146fa0(void);
void baddieInstantiateWeapon(int obj,int state);
void FUN_80146fa4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80147218(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8014721c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11);
void FUN_80147220(double param_1,int param_2,u32 param_3,u16 param_4);
void FUN_80147314(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_801476cc(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80147884(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,float *param_11,float *param_12);
void FUN_80147a70(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80147d2c(int param_1,int param_2);
int Tricky_getExtraSize(void);
u8 Tricky_func0E(int *obj);
u8 Tricky_render2(int *obj);
int Tricky_getCurrentCommandType(int *obj,int *out);
void Tricky_func11(int *obj);
int Tricky_func13(int *obj);
int Tricky_func12(int *obj);
int Tricky_getAvailableCommands(void);

#endif /* MAIN_DLL_COLLECTABLE_H_ */
