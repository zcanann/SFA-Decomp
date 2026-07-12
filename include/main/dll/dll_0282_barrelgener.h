#ifndef MAIN_DLL_DLL_0282_BARRELGENER_H
#define MAIN_DLL_DLL_0282_BARRELGENER_H

#include "main/dll/barrelgener_state.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gBarrelGenerObjDescriptor;

int barrelgener_getLinkId(GameObject* obj);
void barrelgener_queueObjectRelease(GameObject* obj, GameObject* queuedObj, int releaseFrame);
int barrelgener_getExtraSize(void);
int barrelgener_getObjectTypeId(void);
void barrelgener_free(GameObject* obj);
void barrelgener_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void barrelgener_hitDetect(void);
void barrelgener_init(GameObject* obj);
void barrelgener_update(GameObject* obj);
void barrelgener_release(void);
void barrelgener_initialise(void);

#endif
