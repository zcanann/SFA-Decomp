#ifndef DLLS_OBJECTS_568_LINKA_LEVCO_H_
#define DLLS_OBJECTS_568_LINKA_LEVCO_H_

#include "types.h"
#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "main/objseq.h"

extern ObjectDescriptor gLinkALevControlObjDescriptor;

int LinkALevControl_seqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
int LinkALevControl_getExtraSize(void);
int LinkALevControl_getObjectTypeId(void);
void LinkALevControl_free(void);
void LinkALevControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void LinkALevControl_hitDetect(void);
void LinkALevControl_update(GameObject* obj);
void LinkALevControl_init(GameObject* obj);
void LinkALevControl_release(void);
void LinkALevControl_initialise(void);

#endif /* DLLS_OBJECTS_568_LINKA_LEVCO_H_ */
