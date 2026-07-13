#ifndef MAIN_DLL_CAM_DLL_0047_CAMERAMODETESTSTRENGTH_H_
#define MAIN_DLL_CAM_DLL_0047_CAMERAMODETESTSTRENGTH_H_

#include "main/camera_object.h"
#include "types.h"

u32 fn_8010AEA8(CameraObject* camera, u32 flagsIn);
void cameraModeTestStrengthFn_8010b238(f32 fovEnd, CameraObject* camera, f32* posEnd, s32 rotXEnd, s32 rotYEnd,
                                      s32 rotZEnd);
void CameraModeTestStrength_copyToCurrent(void);
void CameraModeTestStrength_free(void);
void CameraModeTestStrength_update(short* camera);
void CameraModeTestStrength_init(short* camera, int unused, int* settings);
void CameraModeTestStrength_release(void);
void CameraModeTestStrength_initialise(void);

#endif /* MAIN_DLL_CAM_DLL_0047_CAMERAMODETESTSTRENGTH_H_ */
