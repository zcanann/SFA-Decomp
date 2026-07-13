#ifndef MAIN_DLL_DLL_00DF_HAGABON_H_
#define MAIN_DLL_DLL_00DF_HAGABON_H_

#include "main/dll/hagabonstate_struct.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gHagabonObjDescriptor;

void Hagabon_release(void);
void Hagabon_initialise(void);
void fn_8014E1DC(GameObject* obj, HagabonState* state);
void Hagabon_hitDetect(GameObject* obj);
void Hagabon_free(GameObject* obj);
void Hagabon_init(GameObject* obj, int data, int skip_alloc);
void Hagabon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int Hagabon_getExtraSize(void);
int Hagabon_getObjectTypeId(void);
void Hagabon_update(int obj);

#endif /* MAIN_DLL_DLL_00DF_HAGABON_H_ */
