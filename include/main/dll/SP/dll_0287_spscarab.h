#ifndef MAIN_DLL_SP_DLL_0287_SPSCARAB_H_
#define MAIN_DLL_SP_DLL_0287_SPSCARAB_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gSPScarabObjDescriptor;

void SPScarab_update(int obj);
void SPScarab_init(GameObject* obj, int def);
void SPScarab_free(int obj);
void SPScarab_release(void);
void SPScarab_initialise(void);
int SPScarab_getExtraSize(void);
int SPScarab_getObjectTypeId(void);
void SPScarab_hitDetect(void);
void SPScarab_render(void);

#endif /* MAIN_DLL_SP_DLL_0287_SPSCARAB_H_ */
