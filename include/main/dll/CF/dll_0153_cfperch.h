#ifndef MAIN_DLL_CF_DLL_0153_CFPERCH_H_
#define MAIN_DLL_CF_DLL_0153_CFPERCH_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

int CFPerch_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int cfperch_getExtraSize(void);
int cfperch_getObjectTypeId(void);
void cfperch_free(GameObject* obj);
void cfperch_render(void);
void cfperch_hitDetect(void);
void cfperch_update(GameObject* obj);
void cfperch_init(GameObject* obj);
void cfperch_release(void);
void cfperch_initialise(void);

extern ObjectDescriptor gCFPerchObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_0153_CFPERCH_H_ */
