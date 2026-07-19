#ifndef MAIN_NEWSHADOWS_SHADOW_API_H_
#define MAIN_NEWSHADOWS_SHADOW_API_H_

#include "main/game_object.h"

void newshadows_getShadowTextureTable4x8(int* tableOut, int* columnsOut, int* rowsOut);
u32 textureFn_8006c5c4(void);
void objShadowFn_8006c5f0(GameObject* obj, u32* outTexture, f32* outScale, int* outX, int* outY);
void shadowCreate(int* obj);
void shadowRenderFn_8006b558(int* obj);
void renderShadows(int unused0, int unused1, int unused2);

#endif /* MAIN_NEWSHADOWS_SHADOW_API_H_ */
