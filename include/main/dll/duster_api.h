#ifndef MAIN_DLL_DUSTER_API_H_
#define MAIN_DLL_DUSTER_API_H_

#include "main/dll/wall_plane_state.h"

void wallPlaneClampMoveTarget(float* outPos, WallPlaneState* plane, float lateral, float height);

extern u8 gDusterEbaMoveTable[];

#endif /* MAIN_DLL_DUSTER_API_H_ */
