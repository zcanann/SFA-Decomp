#ifndef MAIN_DLL_SP_DLL_0287_SPSCARAB_H_
#define MAIN_DLL_SP_DLL_0287_SPSCARAB_H_

#include "game/objects/object.h"
#include "dlls/object_descriptor.h"

extern ObjectDescriptor gSPScarabObjDescriptor;

typedef struct SpscarabPlacement SpscarabPlacement;

void SPScarab_update(GameObject* obj);
void SPScarab_init(GameObject* obj, SpscarabPlacement* def);
void SPScarab_free(GameObject* obj);
void SPScarab_release(void);
void SPScarab_initialise(void);
int SPScarab_getExtraSize(void);
int SPScarab_getObjectTypeId(void);
void SPScarab_hitDetect(void);
void SPScarab_render(void);

#endif /* MAIN_DLL_SP_DLL_0287_SPSCARAB_H_ */
