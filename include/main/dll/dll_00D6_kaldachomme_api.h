#ifndef MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_
#define MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gKaldaChompMeObjDescriptor;

int KaldaChompMe_getExtraSize(void);
int KaldaChompMe_getObjectTypeId(void);
void KaldaChompMe_free(void);
void KaldaChompMe_render(int p1, int p2, int p3, int p4, int p5, s8 renderFlag);
void KaldaChompMe_hitDetect(void);
void KaldaChompMe_update(GameObject* obj);
void KaldaChompMe_init(GameObject* obj, int params);
void KaldaChompMe_release(void);
void KaldaChompMe_initialise(void);
void kaldachompme_setLinkedMouthMode(u8* obj, u8 mode);

#endif /* MAIN_DLL_DLL_00D6_KALDACHOMME_API_H_ */
