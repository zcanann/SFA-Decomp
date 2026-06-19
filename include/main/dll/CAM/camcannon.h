#ifndef MAIN_DLL_CAM_CAMCANNON_H_
#define MAIN_DLL_CAM_CAMCANNON_H_

#include "ghidra_import.h"
#include "main/camera_object.h"

u32 fn_8010AEA8(CameraObject *camera,u32 flagsIn);
void cameraModeTestStrengthFn_8010b238(f32 fovEnd, CameraObject *camera, f32 *posEnd,
                 s32 rotXEnd, s32 rotYEnd, s32 rotZEnd);
void FUN_8010b428(void);

#endif /* MAIN_DLL_CAM_CAMCANNON_H_ */
