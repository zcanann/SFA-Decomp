#ifndef DLLS_OBJECTS_247_H_
#define DLLS_OBJECTS_247_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

typedef struct DllF7Placement DllF7Placement;

int dll_F7_getExtraSize(void);
int dll_F7_getObjectTypeId(void);
void dll_F7_free(GameObject* obj);
void dll_F7_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void dll_F7_hitDetect(void);
void dll_F7_update(GameObject* obj);
void dll_F7_init(GameObject* obj, DllF7Placement* placement);
void dll_F7_release(void);
void dll_F7_initialise(void);

extern ObjectDescriptor gDllF7ObjDescriptor;

#endif /* DLLS_OBJECTS_247_H_ */
