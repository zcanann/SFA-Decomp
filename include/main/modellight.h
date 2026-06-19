#ifndef MAIN_MODELLIGHT_H_
#define MAIN_MODELLIGHT_H_

#include "main/game_object.h"
#include "main/dll/ivec3_struct.h"
#include "main/model_light.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/camera.h"
#include "main/texture.h"

void* objAllocLight(void* owner);
void updateLights(void);

#endif
