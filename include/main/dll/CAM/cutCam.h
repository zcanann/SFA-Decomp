#ifndef MAIN_DLL_CAM_CUTCAM_H_
#define MAIN_DLL_CAM_CUTCAM_H_

#include "ghidra_import.h"
#include "main/camera_object.h"
#include "main/game_object.h"

typedef struct CamcontrolAction43Payload {
  s16 action;
  u8 enabled;
  u8 immediate;
} CamcontrolAction43Payload;

typedef struct CamcontrolAction44Payload {
  f32 distance;
  f32 yOffset;
  s16 height;
} CamcontrolAction44Payload;

#define CAMCONTROL_TRACE_RADIUS_OFFSET 0x40
#define CAMCONTROL_TRACE_BBOX_HIT_OFFSET 0x50
#define CAMCONTROL_TRACE_MODE_OFFSET 0x54
#define CAMCONTROL_TRACE_HIT_COUNT_OFFSET 0x6C
#define CAMCONTROL_TRACE_BLOCKED_OFFSET 0x6E
#define CAMCONTROL_TRACE_WORK_SIZE 0x70

int
camcontrol_traceMove(float *fromPos,float *toPos,float *outPos,u8 *traceWork,
                     char traceMode,u8 runTrace,u8 runBbox,float radius);
u8 camcontrol_traceFromTarget(float *fromPos,GameObject *target,float *outPos);
u8 camcontrol_getTargetPosition(CameraObject *camera,ObjAnimComponent *targetAnim,
                                f32 *outPos,s16 *outRotY);
void camcontrol_updateTargetAction(CameraObject *camera,GameObject *target);
int cameraFn_80103b40(short *cam, f32 *outA, f32 *outB, int angle);
void camMoveFn_80104040(CameraObject *camera, GameObject *target);
void camcontrol_updateModeSettings(int camera);
void doNothing_80103660(int unused);


/* extern-cleanup: consolidated prototypes */
void Rcp_DisableBlurFilter(void);

#endif /* MAIN_DLL_CAM_CUTCAM_H_ */
