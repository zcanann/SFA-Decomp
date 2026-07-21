#ifndef MAIN_NEWSHADOWS_SHADOW_API_H_
#define MAIN_NEWSHADOWS_SHADOW_API_H_

#include "main/game_object.h"
#include "main/texture.h"

void newshadows_getShadowTextureTable4x8(Texture*** tableOut, int* columnsOut, int* rowsOut);
u32 getNewShadowSmallDiskTexture(void);
void getObjectShadowDrawParams(GameObject* obj, u32* outTexture, f32* outScale, int* outX, int* outY);
void shadowCreate(int* obj);
void renderObjectShadowTexture(GameObject* obj);
void renderShadows(int unused0, int unused1, int unused2);

#endif /* MAIN_NEWSHADOWS_SHADOW_API_H_ */
