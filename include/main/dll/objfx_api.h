#ifndef MAIN_DLL_OBJFX_API_H_
#define MAIN_DLL_OBJFX_API_H_

#include "game/objects/object.h"

typedef struct ModelLightStruct ModelLightStruct;

void objDoParticleFx(GameObject* obj, f32 scale, int type, f32 extraScale, ModelLightStruct* light);
void objfx_spawnFrameTimedHitPulse(GameObject* obj, f32 scale, u8 type, u8 frame, f32 intensity);
void objfx_shakeCameraByDistance(GameObject* obj, f32 threshold);
void spawnDimExplosion(GameObject* source, f32 x, f32 y, f32 z, f32 scale, u8 kind, u8 flag4, u8 flag8, u8 flag10,
                       u8 doShake, u8 flag20, u8 initialFlags);

#endif /* MAIN_DLL_OBJFX_API_H_ */
