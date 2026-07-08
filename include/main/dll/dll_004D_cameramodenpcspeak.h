#ifndef MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_
#define MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_

#include "main/game_object.h"

typedef struct CameraModeNpcSpeakInitParams
{
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    u8 mode;
} CameraModeNpcSpeakInitParams;

void CameraModeNpcSpeak_copyToCurrent(void);
void CameraModeNpcSpeak_free(void);
void CameraModeNpcSpeak_release(void);
void CameraModeNpcSpeak_initialise(void);
void CameraModeNpcSpeak_init(u8* obj, int unused, u8* initData);
void CameraModeNpcSpeak_update(u8* obj);
void fn_8010DB7C(GameObject* target, f32* outX, f32* outY, f32* outZ);

#endif /* MAIN_DLL_DLL_004D_CAMERAMODENPCSPEAK_H_ */
