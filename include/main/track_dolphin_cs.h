#ifndef MAIN_TRACK_DOLPHIN_CS_H_
#define MAIN_TRACK_DOLPHIN_CS_H_

#include "main/map_block.h"
#include "main/objanim_internal.h"

void fn_80069B1C(Texture* src1, Texture* src2, f32 blend, Texture* dst);
int fn_800626C8(int* obj, int delta);
void mapGetBlocks(void** outPtr, u32* outVal);
void MapBlock_initShaders(MapBlockData* block);
u32 mapBlockFn_80060678(int* obj);
void fn_800605F0(s16* in, f32* out);
void fn_8006058C(short* out, float* vec);
void fn_80060490(u32* outX, u32* outY, u32* outWidth, u32* outHeight);
void* mapBlockFn_800606ec(int* obj, int idx);

#endif /* MAIN_TRACK_DOLPHIN_CS_H_ */
