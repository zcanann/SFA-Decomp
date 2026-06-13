#ifndef MAIN_DLL_DLL_B6_H_
#define MAIN_DLL_DLL_B6_H_

#include "main/dll/CAM/camcontrol.h"

CamcontrolTargetObject *camcontrol_findBestTarget(CamcontrolCameraState *cameraState,
                                                  ObjAnimComponent *focus);
void camcontrol_updateMoveAverage(CamcontrolCameraState *cameraState, ObjAnimComponent *focus);

#endif /* MAIN_DLL_DLL_B6_H_ */
