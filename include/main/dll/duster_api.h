#ifndef MAIN_DLL_DUSTER_API_H_
#define MAIN_DLL_DUSTER_API_H_

#include "types.h"

/* Shared wall-plane record produced by rachnopFindWallPlane and consumed by
 * the duster/firefly-lantern planar movement helpers. */
typedef struct WallPlaneState
{
    f32 normal[3]; /* 0x00: XYZ plane normal */
    f32 normalW;   /* 0x0C: fourth bbox-hit plane component */
    f32 axisLimit; /* 0x10: lateral limit along the plane */
    f32 anchorY;   /* 0x14 */
    f32 boundMin;  /* 0x18 */
    f32 anchorX;   /* 0x1C */
    f32 anchorZ;   /* 0x20 */
} WallPlaneState;

STATIC_ASSERT(sizeof(WallPlaneState) == 0x24);

void wallPlaneClampMoveTarget(float* outPos, WallPlaneState* plane, float lateral, float height);

extern u8 gDusterEbaMoveTable[];

extern f32 gWallPlaneZero;
extern f32 gWallPlaneOne;

#endif /* MAIN_DLL_DUSTER_API_H_ */
