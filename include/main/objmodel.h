#ifndef MAIN_OBJMODEL_H_
#define MAIN_OBJMODEL_H_

#include "types.h"

int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize);
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize);
void* modelFileGetCollisionBlock(u8* modelFile, int index);
void* modelFileGetCollisionTriangle(u8* modelFile, int index);

#endif /* MAIN_OBJMODEL_H_ */
