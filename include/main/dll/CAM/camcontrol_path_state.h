#ifndef MAIN_DLL_CAM_CAMCONTROL_PATH_STATE_H_
#define MAIN_DLL_CAM_CAMCONTROL_PATH_STATE_H_

#include "main/curve.h"

#define CAMCONTROL_PATH_POINT_CAPACITY 20

typedef struct CamcontrolPathState {
  int localFrameObj;
  f32 actionParamX;
  f32 pad08;
  f32 actionParamZ;
  f32 actionParamY;
  f32 curveMin;
  f32 curveMax;
  f32 pointsX[CAMCONTROL_PATH_POINT_CAPACITY];
  f32 pointsY[CAMCONTROL_PATH_POINT_CAPACITY];
  f32 pointsZ[CAMCONTROL_PATH_POINT_CAPACITY];
  f32 initialiseCurve[5];
  Curve pathCurve;
  u8 active;
  u8 pad1BD[3];
} CamcontrolPathState;

STATIC_ASSERT(sizeof(CamcontrolPathState) == 0x1C0);
STATIC_ASSERT(offsetof(CamcontrolPathState, pointsX) == 0x1C);
STATIC_ASSERT(offsetof(CamcontrolPathState, pointsY) == 0x6C);
STATIC_ASSERT(offsetof(CamcontrolPathState, pointsZ) == 0xBC);
STATIC_ASSERT(offsetof(CamcontrolPathState, initialiseCurve) == 0x10C);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve) == 0x120);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve.dir) == 0x1A0);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve.px) == 0x1A4);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve.count) == 0x1B0);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve.eval) == 0x1B4);
STATIC_ASSERT(offsetof(CamcontrolPathState, pathCurve.coeffFn) == 0x1B8);
STATIC_ASSERT(offsetof(CamcontrolPathState, active) == 0x1BC);

extern CamcontrolPathState *gCamcontrolPathState;

#endif /* MAIN_DLL_CAM_CAMCONTROL_PATH_STATE_H_ */
