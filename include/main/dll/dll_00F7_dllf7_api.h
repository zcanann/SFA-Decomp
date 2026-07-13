#ifndef MAIN_DLL_DLL_00F7_DLLF7_API_H_
#define MAIN_DLL_DLL_00F7_DLLF7_API_H_

#include "types.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor dll_F7;

void dll_F7_free(int obj);
int dll_F7_getExtraSize(void);
int dll_F7_getObjectTypeId(void);
void dll_F7_hitDetect(void);
void dll_F7_init(int* obj, int* params);
void dll_F7_initialise(void);
void dll_F7_release(void);
void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_F7_update(int* obj);

#endif /* MAIN_DLL_DLL_00F7_DLLF7_API_H_ */
