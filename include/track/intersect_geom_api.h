#ifndef TRACK_INTERSECT_GEOM_API_H_
#define TRACK_INTERSECT_GEOM_API_H_

#include "types.h"

typedef struct GameObject GameObject;
typedef struct ObjModel ObjModel;

void gxTevTextureTimesRasStage(void);
/* ObjDef-selected GX callbacks: normal-space disk masking and projected indirect texturing. */
int objModelNormalDiskRenderCb(GameObject* object, ObjModel* model, int slot);
int objModelProjectedIndirectRenderCb(GameObject* object, ObjModel* model, int slot);
u32 objCausticReflectionRenderCb(void* handle, void* model);

#endif /* TRACK_INTERSECT_GEOM_API_H_ */
