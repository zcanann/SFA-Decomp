#ifndef MAIN_NEWSHADOWS_SHADOW_API_H_
#define MAIN_NEWSHADOWS_SHADOW_API_H_

#include "game/objects/object.h"
#include "main/texture.h"

void newshadows_getShadowTextureTable4x8(Texture*** tableOut, int* columnsOut, int* rowsOut);
u32 newshadows_getSmallDiskTexture(void);
void getObjectShadowDrawParams(GameObject* obj, Texture** outTexture, f32* outScale, int* outX, int* outY);
void queueObjectShadow(GameObject* obj);
void renderObjectShadowTexture(GameObject* obj);
void renderShadows(int unused0, int unused1, int unused2);

#endif /* MAIN_NEWSHADOWS_SHADOW_API_H_ */
