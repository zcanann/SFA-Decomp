#ifndef MAIN_LIGHTMAP_INTERNAL_H_
#define MAIN_LIGHTMAP_INTERNAL_H_

#include "main/dll/ppcwgpipe_struct.h"
#include "types.h"

typedef struct EnvironmentUpdateInterface
{
    void (*create)(void);
    void (*destroy)(void);
    void (*update)(void);
} EnvironmentUpdateInterface;

extern EnvironmentUpdateInterface** gEnvironmentUpdateInterface;

/*
 * One 0x10-stride row of gLightmapDrawQueue, the render/shadow queue shared by
 * lightmap.c, lightmap_draw.c and tex_dolphin.c. lightmap_draw.c sorts the rows
 * by key; mapBlockRender_callList writes type (4/5 = object shadow,
 * 6 = indirect lightmap) into the row it queues, and lightmap.c writes the
 * object-shadow kinds 0..3 and 7 into the same field.
 */
typedef struct
{
    u32 a;
    u32 b;
    u32 key;
    u32 type;
} LightSortEntry;

typedef struct MapLayerBuffers
{
    u8 reserved[0x41cc];
    u8* cellStates[5];
    u8* blockDescriptors[5];
    u8* blockIndices[5];
} MapLayerBuffers;

typedef struct
{
    u8 pad[0x4114];
    u32 deferred[20];
} LightmapDrawQueue;

#endif /* MAIN_LIGHTMAP_INTERNAL_H_ */
