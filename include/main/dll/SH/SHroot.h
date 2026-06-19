#ifndef MAIN_DLL_SH_SHROOT_H_
#define MAIN_DLL_SH_SHROOT_H_

#include "main/objanim_update.h"
#include "main/dll/SH/SHthorntail_internal.h"

void SHthorntail_updateRootControlMode3(SHthorntailObject *obj,SHthorntailRuntime *runtime);
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime);
void SHthorntail_updateLevelControlMode1(u32 objectId,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
void SHthorntail_updateLevelControlMode0(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                         SHthorntailConfig *config);
u32 SHthorntail_updateLevelControlState(SHthorntailObject *obj,int unused,
                                               ObjAnimUpdateState *animUpdate);
int SHthorntail_getExtraSize(void);
void SHthorntail_free(SHthorntailObject *obj);

#endif /* MAIN_DLL_SH_SHROOT_H_ */
