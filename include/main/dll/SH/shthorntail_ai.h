#ifndef MAIN_DLL_SH_SHTHORNTAIL_AI_H_
#define MAIN_DLL_SH_SHTHORNTAIL_AI_H_

#include "main/dll/SH/SHthorntail_internal.h"

int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject *obj);
void SHthorntail_updateTailSwing(u32 objectId,SHthorntailRuntime *runtime);
u32 SHthorntail_chooseNextState(SHthorntailObject *obj,SHthorntailRuntime *runtime,
                                 SHthorntailConfig *config);

#endif /* MAIN_DLL_SH_SHTHORNTAIL_AI_H_ */
