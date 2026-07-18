#ifndef MAIN_SHADER_CS2_H_
#define MAIN_SHADER_CS2_H_

#include "types.h"

void mapLoadForObject(int mapId, char* obj);
void mapDebugRender(int* state);
int mapRectFn_8005a728(int bx, int bz, char* obj);
void* mapTextureOverrideGetEntry(int idx);

#endif /* MAIN_SHADER_CS2_H_ */
