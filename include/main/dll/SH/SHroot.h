#ifndef MAIN_DLL_SH_SHROOT_H_
#define MAIN_DLL_SH_SHROOT_H_

#include "main/dll/SH/SHthorntail_internal.h"

void SHthorntail_updateRootControlMode3(SHthorntailObject *obj,SHthorntailRuntime *runtime);
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime);
void SHthorntail_updateLevelControlMode1(uint objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
void SHthorntail_updateLevelControlMode0(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
undefined4 SHthorntail_updateLevelControlState(int obj,undefined4 param_2,int param_3);
int sh_thorntail_getExtraSize(void);
void sh_thorntail_free(SHthorntailObject *obj);

#endif /* MAIN_DLL_SH_SHROOT_H_ */
