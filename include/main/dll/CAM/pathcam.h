#ifndef MAIN_DLL_CAM_PATHCAM_H_
#define MAIN_DLL_CAM_PATHCAM_H_

#include "ghidra_import.h"

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
  undefined4 targetObj;
  f32 localX;
  f32 localY;
  f32 localZ;
  u8 unkB4[4];
  f32 worldX;
  f32 worldY;
  f32 worldZ[33];
} CamcontrolPathSampleWork;

void pathcam_loadSettings(undefined2 *param_1,int param_2,int param_3);
void camcontrol_releaseModeSettings(void);
void camcontrol_initialiseModeSettings(void);
void camcontrol_samplePathState(f32 *outX,f32 *height,f32 *outZ,undefined4 param_4,int param_5);

#endif /* MAIN_DLL_CAM_PATHCAM_H_ */
