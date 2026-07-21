#ifndef MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_
#define MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_

#include "main/camera_object.h"
#include "main/game_object.h"

typedef struct CameraModeNpcSpeakInitParams
{
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 mode;
} CameraModeNpcSpeakInitParams;

STATIC_ASSERT(offsetof(CameraModeNpcSpeakInitParams, mode) == 0xC);
STATIC_ASSERT(sizeof(CameraModeNpcSpeakInitParams) == 0x10);

void CameraModeNpcSpeak_copyToCurrent(void);
void CameraModeNpcSpeak_free(void);
void CameraModeNpcSpeak_release(void);
void CameraModeNpcSpeak_initialise(void);
void CameraModeNpcSpeak_init(CameraObject* camera, int unused, CameraModeNpcSpeakInitParams* params);
void CameraModeNpcSpeak_update(CameraObject* camera);
void CameraModeNpcSpeak_solveOrbitPosition(GameObject* target, f32* outX, f32* outY, f32* outZ);

#endif /* MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_ */
