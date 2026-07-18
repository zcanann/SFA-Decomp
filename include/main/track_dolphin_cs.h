#ifndef MAIN_TRACK_DOLPHIN_CS_H_
#define MAIN_TRACK_DOLPHIN_CS_H_

#include "main/map_block.h"
#include "main/objanim_internal.h"
#include "main/track_dolphin_map_api.h"

void fn_80069B1C(Texture* src1, Texture* src2, f32 blend, Texture* dst);
int fn_800626C8(int* obj, int delta);
void mapGetBlocks(void** outPtr, u32* outVal);
void MapBlock_initShaders(MapBlockData* block);
void fn_800605F0(s16* in, f32* out);
void fn_8006058C(short* out, float* vec);

#endif /* MAIN_TRACK_DOLPHIN_CS_H_ */
