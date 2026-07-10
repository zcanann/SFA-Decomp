#ifndef MAIN_DLL_DR_DLL_0287_SPSCARAB_H_
#define MAIN_DLL_DR_DLL_0287_SPSCARAB_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gSPScarabObjDescriptor;

void SPScarab_update(int obj);
void SPScarab_init(GameObject* obj, int def);
void SPScarab_release(void);
void SPScarab_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0287_SPSCARAB_H_ */
