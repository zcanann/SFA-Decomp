#ifndef MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_
#define MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_

#include "main/objanim_update.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gDepthOfFieldPointObjDescriptor;

int depthoffieldpoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int depthoffieldpoint_getExtraSize(void);
void depthoffieldpoint_init(int* obj);
void depthoffieldpoint_update(int* obj);

#endif /* MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_ */
