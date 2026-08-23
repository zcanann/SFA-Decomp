#ifndef MAIN_TRACK_BBOX_API_H_
#define MAIN_TRACK_BBOX_API_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/track_line_intersect_result.h"

#ifndef TRACK_BBOX_ARG10_TYPE
#define TRACK_BBOX_ARG10_TYPE u8
#endif

#ifndef TRACK_BBOX_MASK_TYPE
#define TRACK_BBOX_MASK_TYPE int
#endif

#ifdef TRACK_BBOX_FLAGS_S8
int trackGetLineIntersect(f32* from, f32* to, f32 radius, int mode, TrackLineIntersectResult* hit, GameObject* self,
                          s8 flags, TRACK_BBOX_MASK_TYPE mask, int slot, TRACK_BBOX_ARG10_TYPE arg10);
#else
int trackGetLineIntersect(f32* from, f32* to, f32 radius, int mode, TrackLineIntersectResult* hit, GameObject* self,
                          int flags, TRACK_BBOX_MASK_TYPE mask, int slot, TRACK_BBOX_ARG10_TYPE arg10);
#endif

#endif /* MAIN_TRACK_BBOX_API_H_ */
