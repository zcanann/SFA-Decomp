#ifndef MAIN_TRACK_BBOX_API_H_
#define MAIN_TRACK_BBOX_API_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/track_line_intersect_result.h"

#ifdef TRACK_BBOX_FLAGS_S8
int trackGetLineIntersect(f32* startPos, f32* endPos, f32 radius, int flags, TrackLineIntersectResult* hit,
                          GameObject* self, s8 lineMask, s8 segment, int slot, s8 yTolerance);
#else
int trackGetLineIntersect(f32* startPos, f32* endPos, f32 radius, int flags, TrackLineIntersectResult* hit,
                          GameObject* self, int lineMask, s8 segment, int slot, s8 yTolerance);
#endif

#endif /* MAIN_TRACK_BBOX_API_H_ */
