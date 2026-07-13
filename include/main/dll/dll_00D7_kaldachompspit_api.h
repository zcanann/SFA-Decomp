#ifndef MAIN_DLL_DLL_00D7_KALDACHOMPSPIT_API_H_
#define MAIN_DLL_DLL_00D7_KALDACHOMPSPIT_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gKaldaChompSpitObjDescriptor;

void KaldaChompSpit_free(int* obj);
int KaldaChompSpit_getExtraSize(void);
int KaldaChompSpit_getObjectTypeId(void);
void KaldaChompSpit_hitDetect(void);
void KaldaChompSpit_init(GameObject* obj);
void KaldaChompSpit_initialise(void);
void KaldaChompSpit_release(void);
void KaldaChompSpit_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void KaldaChompSpit_update(int obj);

#endif /* MAIN_DLL_DLL_00D7_KALDACHOMPSPIT_API_H_ */
