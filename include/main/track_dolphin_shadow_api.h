#ifndef MAIN_TRACK_DOLPHIN_SHADOW_API_H_
#define MAIN_TRACK_DOLPHIN_SHADOW_API_H_

#include "main/map_block.h"
#include "main/objanim_internal.h"
#include "main/track_dolphin_map_api.h"

typedef struct GameObject GameObject;

u8 objShadowUpdateAlpha(GameObject* obj, int delta);
void mapGetBlocks(void** outLayerTables, u32* outBlocks);
void MapBlock_initShaders(MapBlockData* block);

#endif /* MAIN_TRACK_DOLPHIN_SHADOW_API_H_ */
