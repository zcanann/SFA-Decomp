#ifndef MAIN_DLL_DLL_00D9_POLLEN_API_H_
#define MAIN_DLL_DLL_00D9_POLLEN_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gPollenObjDescriptor;

int Pollen_getExtraSize(void);
int Pollen_getObjectTypeId(void);
void Pollen_free(int obj);
void Pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void Pollen_hitDetect(GameObject* obj);
void Pollen_update(int obj);
void Pollen_init(GameObject* obj);
void Pollen_release(void);
void Pollen_initialise(void);

#endif /* MAIN_DLL_DLL_00D9_POLLEN_API_H_ */
