#ifndef MAIN_TRACK_DOLPHIN_SHADOW_API_H_
#define MAIN_TRACK_DOLPHIN_SHADOW_API_H_

#include "main/map_block.h"
#include "main/objanim_internal.h"
#include "main/track_dolphin_map_api.h"

typedef struct GameObject GameObject;

void fn_80069B1C(Texture* src1, Texture* src2, f32 blend, Texture* dst);
u8 fn_800626C8(GameObject* obj, int delta);
void mapGetBlocks(void** outPtr, u32* outVal);
void MapBlock_initShaders(MapBlockData* block);

#endif /* MAIN_TRACK_DOLPHIN_SHADOW_API_H_ */
