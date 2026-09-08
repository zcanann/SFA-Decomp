#ifndef MAIN_OBJMODEL_H_
#define MAIN_OBJMODEL_H_

#include "types.h"

typedef struct ModelFileHeader ModelFileHeader;
typedef struct ModelCollisionTriangle ModelCollisionTriangle;
typedef struct CollisionPolygonGroup CollisionPolygonGroup;

int ObjModel_IsPackedResource(u8* resource);
int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize);
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize);
CollisionPolygonGroup* modelFileGetCollisionBlock(ModelFileHeader* modelFile, int index);
ModelCollisionTriangle* modelFileGetCollisionTriangle(ModelFileHeader* modelFile, int index);

#endif /* MAIN_OBJMODEL_H_ */
