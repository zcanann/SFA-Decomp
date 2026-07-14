#ifndef MAIN_NEWSHADOWS_SHADOW_API_H_
#define MAIN_NEWSHADOWS_SHADOW_API_H_

#include "main/game_object.h"

void newshadows_getShadowTextureTable4x8(int* tableOut, int* columnsOut, int* rowsOut);
void objShadowFn_8006c5f0(GameObject* obj, u32* outTexture, f32* outScale, int* outX, int* outY);

/* Preserve the raw object-address view used by partially typed render code. */
#define objShadowFn_8006c5f0Legacy(obj, outTexture, outScale, outX, outY)                                                \
    ((void (*)(void*, int*, f32*, int*, int*))objShadowFn_8006c5f0)((obj), (outTexture), (outScale), (outX), (outY))

#endif /* MAIN_NEWSHADOWS_SHADOW_API_H_ */
