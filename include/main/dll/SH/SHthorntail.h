#ifndef MAIN_DLL_SH_SHTHORNTAIL_H_
#define MAIN_DLL_SH_SHTHORNTAIL_H_

#include "ghidra_import.h"
#include "main/dll/SH/SHthorntail_internal.h"

int SHthorntail_getExtraSize(void);
void SHthorntail_free(SHthorntailObject *obj);
void SHthorntail_render(SHthorntailObject *obj, int p2, int p3, int p4, int p5, s8 visible);
void SHthorntail_update(SHthorntailObject *obj);
void SHthorntail_init(SHthorntailObject *obj, SHthorntailConfig *config);
void SHthorntail_updateState(SHthorntailObject *obj,SHthorntailRuntime *runtime);

#endif /* MAIN_DLL_SH_SHTHORNTAIL_H_ */
