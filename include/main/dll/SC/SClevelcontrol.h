#ifndef MAIN_DLL_SC_SCLEVELCONTROL_H_
#define MAIN_DLL_SC_SCLEVELCONTROL_H_

#include "main/dll/SH/SHthorntail_internal.h"

void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
void SHthorntail_updateLevelControlMode0(double param_1,undefined8 param_2,undefined8 param_3,
                                         undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                         undefined8 param_7,undefined8 param_8,
                                         SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config,uint param_12,float *param_13,
                                         undefined4 param_14,
                                         undefined4 param_15,undefined4 param_16);
undefined4
SHthorntail_updateLevelControlState(double param_1,double param_2,double param_3,undefined8 param_4,
                                    undefined8 param_5,undefined8 param_6,undefined8 param_7,
                                    undefined8 param_8,SHthorntailObject *obj,undefined4 param_10,
                                    int param_11,undefined4 param_12,undefined4 param_13,
                                    undefined4 param_14,undefined4 param_15,undefined4 param_16);

#endif /* MAIN_DLL_SC_SCLEVELCONTROL_H_ */
