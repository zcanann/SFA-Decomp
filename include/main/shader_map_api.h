#ifndef MAIN_SHADER_MAP_API_H_
#define MAIN_SHADER_MAP_API_H_

#include "game/objects/object.h"
#include "main/map_block.h"
#include "main/map_texture_state.h"
#include "main/model_render_instrs_api.h"

void mapLoadForObject(int mapId, GameObject* obj);
void mapDebugRender(ModelRenderInstrsState* state);
int mapBlockIsInViewFrustum(int bx, int bz, struct MapBlockData* block);
void loadMapForCameraPos(float x, float y, float z);
MapTextureOverride* mapTextureOverrideGetEntry(int idx);

#endif /* MAIN_SHADER_MAP_API_H_ */
