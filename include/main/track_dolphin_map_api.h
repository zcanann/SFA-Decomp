#ifndef MAIN_TRACK_DOLPHIN_MAP_API_H_
#define MAIN_TRACK_DOLPHIN_MAP_API_H_

#include "types.h"

void* mapBlockGetPolygonGroup(void* block, int index);
int mapBlockFn_80060678(void* entry);
void trackUnpackVector(s16* in, f32* out);
void trackPackVector(s16* out, f32* in);

#endif /* MAIN_TRACK_DOLPHIN_MAP_API_H_ */
