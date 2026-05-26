#ifndef MAIN_DLL_SH_SHROCKETMUSHROOM_H_
#define MAIN_DLL_SH_SHROCKETMUSHROOM_H_

#include "ghidra_import.h"

void bombplantingspot_init(void *obj, void *param2);
void bombplantingspot_update(void *obj);
void bombplantspore_update(void *obj);
void bombplantspore_init(void *obj, void *param2);
int sh_queenearthwalker_processAnimEvents(void *obj, void *unused, void *p5);

#endif /* MAIN_DLL_SH_SHROCKETMUSHROOM_H_ */
