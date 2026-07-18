#ifndef MAIN_DLL_DUSTER_API_H_
#define MAIN_DLL_DUSTER_API_H_

#include "types.h"

void wallPlaneClampMoveTarget(float* outPos, float* anchor, float lateral, float height);

extern u8 gDusterEbaMoveTable[];

#endif /* MAIN_DLL_DUSTER_API_H_ */
