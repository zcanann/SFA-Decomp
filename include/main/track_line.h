#ifndef MAIN_TRACK_LINE_H_
#define MAIN_TRACK_LINE_H_

#include <stddef.h>
#include "global.h"
#include "types.h"

/* Built collision lines use indices into the owning point array. The low six
 * kind bits select the sort group; 0x14 marks a consumed scratch entry. */
typedef struct IntersectLine {
    u8 end0;
    u8 end1;
    u8 flags;
    s8 kind;
    s16 pt[2];
    s16 adj[2];
    s16 param;
    u8 pad0E[2];
} IntersectLine;

/* Half-open range in a model's sorted line array, selected by line kind. */
typedef struct TrackModelLineRange {
    u8 first;
    u8 end;
} TrackModelLineRange;

STATIC_ASSERT(sizeof(IntersectLine) == 0x10);
STATIC_ASSERT(offsetof(IntersectLine, flags) == 0x02);
STATIC_ASSERT(offsetof(IntersectLine, kind) == 0x03);
STATIC_ASSERT(offsetof(IntersectLine, pt) == 0x04);
STATIC_ASSERT(offsetof(IntersectLine, adj) == 0x08);
STATIC_ASSERT(offsetof(IntersectLine, param) == 0x0C);
STATIC_ASSERT(sizeof(TrackModelLineRange) == 0x02);
STATIC_ASSERT(offsetof(TrackModelLineRange, first) == 0x00);
STATIC_ASSERT(offsetof(TrackModelLineRange, end) == 0x01);

#endif
