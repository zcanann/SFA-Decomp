#ifndef MAIN_DLL_CF_CFTOGGLESWITCH_H_
#define MAIN_DLL_CF_CFTOGGLESWITCH_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gMagicCaveBottomObjDescriptor;
extern ObjectDescriptor gMagicCaveTopObjDescriptor;
extern ObjectDescriptor gTrickyGuardSpotObjDescriptor;
extern ObjectDescriptor gInfoTextObjDescriptor;
extern ObjectDescriptor gCCTestInfotObjDescriptor;
extern ObjectDescriptor gDeathGasObjDescriptor;

void magiccavebottom_update(undefined4 param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void FUN_8018aee4(void);
void FUN_8018af08(int param_1);
void FUN_8018af28(int param_1);
void FUN_8018af74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_8018b220(undefined2 *param_1);
void FUN_8018b224(void);
void FUN_8018b258(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_8018b5a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_8018b6ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
int magiccavetop_getExtraSize(void);
int trickyguardspot_getExtraSize(void);
int infotext_getExtraSize(void);
int cctestinfot_getExtraSize(void);
int deathgas_getExtraSize(void);
void trickyguardspot_free(int x);
void trickyguardspot_render(void);

#endif /* MAIN_DLL_CF_CFTOGGLESWITCH_H_ */
