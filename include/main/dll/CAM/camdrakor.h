#ifndef MAIN_DLL_CAM_CAMDRAKOR_H_
#define MAIN_DLL_CAM_CAMDRAKOR_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

void CameraModeCombat_update(short *cam);
void CameraModeCombat_init(CameraObject *camera,u32 param_2,GameObject **target);
void FUN_8010cdf4(void);
void CameraModeShipBattle_update(short *cam);
void CameraModeShipBattle_init(void);
void FUN_8010d450(void);

#endif /* MAIN_DLL_CAM_CAMDRAKOR_H_ */
