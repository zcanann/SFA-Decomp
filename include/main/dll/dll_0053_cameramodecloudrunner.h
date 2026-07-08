#ifndef MAIN_DLL_DLL_0053_CAMERAMODECLOUDRUNNER_H_
#define MAIN_DLL_DLL_0053_CAMERAMODECLOUDRUNNER_H_

#include "global.h"

/* object-placement transform fed to setMatrixFromObjectPos() (24 bytes) */
typedef struct CloudRunnerObjectPos
{
    s16 angles[3];
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CloudRunnerObjectPos;

void CameraModeCloudRunner_copyToCurrent(void);
void CameraModeCloudRunner_free(void);
void CameraModeCloudRunner_update(u8* obj);
void CameraModeCloudRunner_init(int* camera, int radius, f32* focus);
void CameraModeCloudRunner_release(void);
void CameraModeCloudRunner_initialise(void);

#endif /* MAIN_DLL_DLL_0053_CAMERAMODECLOUDRUNNER_H_ */
