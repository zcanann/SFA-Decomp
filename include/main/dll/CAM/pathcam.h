#ifndef MAIN_DLL_CAM_PATHCAM_H_
#define MAIN_DLL_CAM_PATHCAM_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

typedef struct CamcontrolPathSampleWork {
  u8 unk0[0xc];
  f32 sampleX;
  f32 sampleY;
  f32 sampleZ;
  f32 targetX;
  f32 targetY;
  f32 targetZ[4];
  int model;
  u8 unk34[0x70];
  GameObject *targetObj;
  f32 localX;
  f32 localY;
  f32 localZ;
  u8 unkB4[4];
  f32 worldX;
  f32 worldY;
  f32 worldZ[33];
} CamcontrolPathSampleWork;

void CameraModeNormal_init(CameraObject *cam, int mode, u8 *data);
void CameraModeNormal_release(void);
void CameraModeNormal_initialise(void);
u8 camcontrol_samplePathState(f32 *outX,f32 *height,f32 *outZ,GameObject *target,
                              CameraObject *camera);

#endif /* MAIN_DLL_CAM_PATHCAM_H_ */
