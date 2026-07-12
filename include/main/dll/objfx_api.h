#ifndef MAIN_DLL_OBJFX_API_H_
#define MAIN_DLL_OBJFX_API_H_

#include "main/game_object.h"

typedef struct ModelLightStruct ModelLightStruct;

void objParticleFn_80099d84(GameObject* obj, f32 scale, int type, f32 extraScale,
                            ModelLightStruct* light);

#endif /* MAIN_DLL_OBJFX_API_H_ */
