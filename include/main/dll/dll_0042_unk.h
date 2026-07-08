#ifndef MAIN_DLL_DLL_0042_UNK_H_
#define MAIN_DLL_DLL_0042_UNK_H_

#include "global.h"
#include "main/camera_object.h"
#include "main/game_object.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"

typedef struct CamSlideRot
{
    s16 angles[4];
    f32 scale;
    f32 transX;
    f32 transY;
    f32 transZ;
} CamSlideRot;

STATIC_ASSERT(offsetof(CamSlideRot, angles) == 0x00);
STATIC_ASSERT(offsetof(CamSlideRot, scale) == 0x08);
STATIC_ASSERT(offsetof(CamSlideRot, transZ) == 0x14);

typedef struct CamSlideObjectState
{
    u8 unk00[0x1A4];
    f32 vectorX;
    f32 vectorY;
    f32 vectorZ;
} CamSlideObjectState;

STATIC_ASSERT(offsetof(CamSlideObjectState, vectorX) == 0x1A4);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorY) == 0x1A8);
STATIC_ASSERT(offsetof(CamSlideObjectState, vectorZ) == 0x1AC);

void camcontrol_updateVerticalBounds(CameraObject* camera, int flags, int collisionFlag, float* upperBound,
                                     float* lowerBound);
void CameraModeNormal_func0A(float* minDistanceOut, float* maxDistanceOut, float* lowerHeightOffsetOut,
                             float* upperHeightOffsetOut, float* targetHeightOut);
void camslide_update(CameraObject* camera, GameObject* target, f32 upperBound, f32 lowerBound);
void firstperson_updatePitch(f32 targetY, f32 dist, CameraObject* camera);
void CameraModeNormal_follow(CameraObject* camera, ObjAnimComponent* target);
void CameraModeNormal_copyToCurrent(CamcontrolFirstPersonActionSettings* settings);
void CameraModeNormal_free(CameraObject* camera);
void CameraModeNormal_update(u8* obj);
void CameraModeNormal_init(CameraObject* cam, int mode, u8* data);
void CameraModeNormal_release(void);
void CameraModeNormal_initialise(void);

#endif
