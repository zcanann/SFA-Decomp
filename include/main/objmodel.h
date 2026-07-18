#ifndef MAIN_OBJMODEL_H_
#define MAIN_OBJMODEL_H_

#include "types.h"

int ObjModel_GetUnpackedResourceSize(u8* resource, int baseSize);
void ObjModel_UnpackResourcePayload(u8* src, int srcSize, u8* dst, int dstSize);
void* fn_80028364(u8* modelFile, int index);
void* fn_80028354(u8* modelFile, int index);

#endif /* MAIN_OBJMODEL_H_ */
