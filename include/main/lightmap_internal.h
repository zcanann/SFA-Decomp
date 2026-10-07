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

struct GameObject;
struct MapBlockBoundsRec;
struct MapBlockData;

/* Shared by queue producers, the depth sorter and the dispatch loop. */
typedef struct LightmapDrawEntry {
    union {
        struct GameObject* object;
        struct MapBlockBoundsRec* bounds;
        void* effectPool;
    } arg0;
    union {
        u32 poolIndex;
        struct MapBlockData* block;
    } arg1;
    u32 key;
    u32 type;
} LightmapDrawEntry;

/* The queue flushes at 1,000 entries. The following bytes remain unidentified. */
typedef struct MapRenderQueueStorage {
    LightmapDrawEntry entries[1000];
    u8 opaqueTail[0xC8];
} MapRenderQueueStorage;

STATIC_ASSERT(sizeof(LightmapDrawEntry) == 0x10);
STATIC_ASSERT(offsetof(LightmapDrawEntry, arg0) == 0);
STATIC_ASSERT(offsetof(LightmapDrawEntry, arg1) == 4);
STATIC_ASSERT(offsetof(LightmapDrawEntry, key) == 8);
STATIC_ASSERT(offsetof(LightmapDrawEntry, type) == 12);
STATIC_ASSERT(offsetof(MapRenderQueueStorage, opaqueTail) == 0x3E80);
STATIC_ASSERT(sizeof(MapRenderQueueStorage) == 0x3F48);

#endif /* MAIN_LIGHTMAP_INTERNAL_H_ */
