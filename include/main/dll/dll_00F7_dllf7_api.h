#ifndef MAIN_DLL_DLL_00F7_DLLF7_API_H_
#define MAIN_DLL_DLL_00F7_DLLF7_API_H_

#include "types.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct DllF7Placement DllF7Placement;

extern ObjectDescriptor dll_F7;

void dll_F7_free(GameObject* obj);
int dll_F7_getExtraSize(void);
int dll_F7_getObjectTypeId(void);
void dll_F7_hitDetect(void);
void dll_F7_init(GameObject* obj, DllF7Placement* placement);
void dll_F7_initialise(void);
void dll_F7_release(void);
void dll_F7_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_F7_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00F7_DLLF7_API_H_ */
