#ifndef MAIN_DLL_DLL_00C6_ANIMATEDOBJ_API_H_
#define MAIN_DLL_DLL_00C6_ANIMATEDOBJ_API_H_

#include "types.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gAnimatedObjDescriptor;

void animatedobj_free(int* obj, int seqFlag);
int animatedobj_getExtraSize(void);
void animatedobj_init(int* obj, int* params);
void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void animatedobj_update(int* obj);

#endif /* MAIN_DLL_DLL_00C6_ANIMATEDOBJ_API_H_ */
