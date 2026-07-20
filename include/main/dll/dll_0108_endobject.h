#ifndef MAIN_DLL_DLL_0108_ENDOBJECT_H_
#define MAIN_DLL_DLL_0108_ENDOBJECT_H_

#include "main/object_descriptor.h"

int EndObject_getExtraSize(void);
int EndObject_getObjectTypeId(void);
void EndObject_free(void);
void EndObject_render(void);
void EndObject_hitDetect(void);
void EndObject_update(void);
void EndObject_init(void);
void EndObject_release(void);
void EndObject_initialise(void);

extern ObjectDescriptor gEndObjectObjDescriptor;

#endif /* MAIN_DLL_DLL_0108_ENDOBJECT_H_ */
