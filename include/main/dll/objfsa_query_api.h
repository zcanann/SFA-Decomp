#ifndef MAIN_DLL_OBJFSA_QUERY_API_H_
#define MAIN_DLL_OBJFSA_QUERY_API_H_

#include "types.h"

typedef struct ObjfsaWalkGroupPatchInfo ObjfsaWalkGroupPatchInfo;

int Objfsa_GetWalkGroupIndexAtPoint(f32* point, ObjfsaWalkGroupPatchInfo* patchInfo);

#endif /* MAIN_DLL_OBJFSA_QUERY_API_H_ */
