#ifndef MAIN_DLL_SH_SHROOT_H_
#define MAIN_DLL_SH_SHROOT_H_

#include "main/dll/SH/SHthorntail_internal.h"

void SHthorntail_updateRootControlMode3(double param_1,undefined8 param_2,undefined8 param_3,
                                        undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                        undefined8 param_7,undefined8 param_8,
                                        SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                        int param_11,uint param_12,float *param_13,
                                        undefined4 param_14,undefined4 param_15,
                                        undefined4 param_16);
void SHthorntail_updateRootControlMode2(double param_1,undefined8 param_2,undefined8 param_3,
                                        undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                        undefined8 param_7,undefined8 param_8,
                                        SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                        int param_11,uint param_12,float *param_13,
                                        undefined4 param_14,undefined4 param_15,
                                        undefined4 param_16);
void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
void SHthorntail_updateLevelControlMode0(double param_1,undefined8 param_2,undefined8 param_3,
                                         undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                         undefined8 param_7,undefined8 param_8,
                                         SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config,uint param_12,float *param_13,
                                         undefined4 param_14,
                                         undefined4 param_15,undefined4 param_16);
undefined4 SHthorntail_updateLevelControlState(int obj,undefined4 param_2,int param_3);
int sh_thorntail_getExtraSize(void);
void sh_thorntail_free(SHthorntailObject *obj);

#endif /* MAIN_DLL_SH_SHROOT_H_ */
