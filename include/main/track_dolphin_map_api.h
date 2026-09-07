#ifndef MAIN_TRACK_DOLPHIN_MAP_API_H_
#define MAIN_TRACK_DOLPHIN_MAP_API_H_

#include "types.h"
#include "main/map_block.h"

MapTriIndex* mapBlockGetPolygon(MapBlockData* block, int index);
CollisionPolygonGroup* mapBlockGetPolygonGroup(MapBlockData* block, int index);
int mapBlockGetPolygonGroupType(void* entry);
u32 trackGetPackedSurfaceType(CollisionPolygonGroup* group);
void trackUnpackVector(s16* in, f32* out);
void trackPackVector(s16* out, f32* in);

#endif /* MAIN_TRACK_DOLPHIN_MAP_API_H_ */
