#ifndef MAIN_DLL_DLL_00D8_PINPONSPIKE_API_H_
#define MAIN_DLL_DLL_00D8_PINPONSPIKE_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gPinPonSpikeObjDescriptor;

int pinponspike_getExtraSize(void);
int pinponspike_getObjectTypeId(void);
void pinponspike_free(int obj);
void pinponspike_render(void);
void pinponspike_hitDetect(void);
void pinponspike_update(int obj);
void pinponspike_init(GameObject* obj);
void pinponspike_release(void);
void pinponspike_initialise(void);

#endif /* MAIN_DLL_DLL_00D8_PINPONSPIKE_API_H_ */
