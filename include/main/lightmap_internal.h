#ifndef MAIN_LIGHTMAP_INTERNAL_H_
#define MAIN_LIGHTMAP_INTERNAL_H_

#include "main/dll/ppcwgpipe_struct.h"
#include "global.h"
#include <stddef.h>

typedef struct EnvironmentUpdateInterface {
    void (*create)(void);
    void (*destroy)(void);
    void (*update)(void);
} EnvironmentUpdateInterface;

extern EnvironmentUpdateInterface** gEnvironmentUpdateInterface;

/*
 * One 0x10-stride row of gLightmapDrawQueue, the render/shadow queue shared by
 * the map-rendering unit in shader.c. lightmap_sortTransparentDrawQueue sorts
 * the rows by key; mapBlockRender_callList writes type (4/5 = object shadow,
 * 6 = indirect lightmap), and renderObjects writes the object-shadow kinds
 * into the same field.
 */
typedef struct {
    u32 a;
    u32 b;
    u32 key;
    u32 type;
} LightSortEntry;

/* The queue flushes at 1,000 entries. The following bytes remain unidentified. */
typedef struct MapRenderQueueStorage {
    LightSortEntry entries[1000];
    u8 opaqueTail[0xC8];
} MapRenderQueueStorage;

STATIC_ASSERT(sizeof(LightSortEntry) == 0x10);
STATIC_ASSERT(offsetof(MapRenderQueueStorage, opaqueTail) == 0x3E80);
STATIC_ASSERT(sizeof(MapRenderQueueStorage) == 0x3F48);

struct MapCellEntry;

/* Address view of the layer tables relative to the cached render-queue base. */
typedef struct MapLayerBuffers {
    u8 reserved[0x41cc];
    s8* cellStates[5];
    struct MapCellEntry* cellEntries[5];
    s8* blockIndices[5];
} MapLayerBuffers;

STATIC_ASSERT(offsetof(MapLayerBuffers, cellStates) == 0x41CC);
STATIC_ASSERT(offsetof(MapLayerBuffers, cellEntries) == 0x41E0);
STATIC_ASSERT(offsetof(MapLayerBuffers, blockIndices) == 0x41F4);

typedef struct {
    u8 pad[0x4114];
    u32 deferred[20];
} LightmapDrawQueue;

#endif /* MAIN_LIGHTMAP_INTERNAL_H_ */
