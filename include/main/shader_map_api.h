#ifndef MAIN_SHADER_MAP_API_H_
#define MAIN_SHADER_MAP_API_H_

#include "main/game_object.h"

void mapLoadForObject(int mapId, GameObject* obj);
void mapDebugRender(int* state);
int mapRectFn_8005a728(int bx, int bz, u8* obj);
void loadMapForCameraPos(float x, float y, float z);
void* mapTextureOverrideGetEntry(int idx);

#endif /* MAIN_SHADER_MAP_API_H_ */
