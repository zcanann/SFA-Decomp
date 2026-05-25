#include "ghidra_import.h"
#include "main/dll/CAM/camcontrol.h"
#include "main/dll/dll_B8.h"

extern CameraViewSlot *Camera_GetCurrentViewSlot(void);
extern float Camera_GetFovY(void);
extern f32 lbl_803E162C;
extern u8 *pCamera;

#pragma scheduling off
#pragma peephole off
void firstPersonZoomOutOnExit(byte param_1, byte param_2)
{
  CameraViewSlot *vs;

  float fov_const;

  Camera_GetCurrentViewSlot();
  fov_const = lbl_803E162C;
  *(float *)(pCamera + 0xf4) = fov_const;
  *(float *)(pCamera + 0xf8) = fov_const / (float)param_1;
  pCamera[0x13f] = param_2;

  vs = Camera_GetCurrentViewSlot();
  *(float *)(pCamera + 0x10c) = vs->x;
  *(float *)(pCamera + 0x110) = vs->y;
  *(float *)(pCamera + 0x114) = vs->z;
  *(short *)(pCamera + 0x106) = vs->yaw;
  *(short *)(pCamera + 0x108) = vs->pitch;
  *(short *)(pCamera + 0x10a) = vs->roll;

  *(float *)(pCamera + 0x118) = Camera_GetFovY();
}
#pragma peephole reset
#pragma scheduling reset

void cameraSetInterpMode(u8 v) { pCamera[0x139] = v; }
