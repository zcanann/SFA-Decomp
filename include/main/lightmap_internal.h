#ifndef MAIN_LIGHTMAP_INTERNAL_H_
#define MAIN_LIGHTMAP_INTERNAL_H_

#include "main/dll/ppcwgpipe_struct.h"
#include "global.h"
#include "main/map_romlist_page.h"
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

struct GameObject;

/* Address view of gLightmapDeferredObjects relative to the cached render-queue
 * base. The list is a separate BSS object, not part of MapRenderQueueStorage. */
typedef struct MapDeferredObjectListView {
    u8 reserved[0x4114];
    struct GameObject* deferred[20];
} MapDeferredObjectListView;

STATIC_ASSERT(offsetof(MapDeferredObjectListView, deferred) == 0x4114);
STATIC_ASSERT(sizeof(((MapDeferredObjectListView*)0)->deferred) == 0x50);

#endif /* MAIN_LIGHTMAP_INTERNAL_H_ */
