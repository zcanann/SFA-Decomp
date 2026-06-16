/*
 * Texture-resource cache for the expgfx (explosion/effect graphics) system.
 * EXPGFX_RUNTIME_DATA->resourceTable holds EXPGFX_RESOURCE_TABLE_COUNT entries,
 * each caching one loaded texture by resourceId.
 *
 * expgfx_updateResourceEntries ages every live entry by framesThisStep and
 * frees it (via textureFree, guarded by gExpgfxTextureFreeInProgress) once its
 * eviction score hits zero. expgfx_acquireResourceEntry returns the slot index
 * for a resource: it reuses a matching live entry, else loads into a free slot,
 * else - only while loading is locked (Obj_IsLoadingLocked) - evicts the
 * lowest-scoring entry and reloads. A texture whose refCount has reached
 * EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT is treated as busy and rejected.
 */
#include "main/engine_shared.h"
#include "main/expgfx_internal.h"
#include "main/texture.h"

void expgfx_updateResourceEntries(int unused)
{
    ExpgfxResourceEntry* entry;
    int i;

    i = 0;
    entry = EXPGFX_RUNTIME_DATA->resourceTable;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++)
    {
        if (entry->resourceId != 0)
        {
            entry->evictionScore = entry->evictionScore - framesThisStep;
            if (entry->evictionScore <= 0)
            {
                entry->resourceId = 0;
                entry->evictionScore = 0;
                entry->reserved = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree((u8*)entry->resource);
                gExpgfxTextureFreeInProgress = 0;
                entry->resource = NULL;
            }
        }
        entry++;
    }
}

int expgfx_acquireResourceEntry(int resourceId)
{
    ExpgfxResourceEntry* entry;
    ExpgfxResourceHandle* resourceHandle;
    int minEvictionScore;
    int minIndex;
    int i;

    i = 0;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++)
    {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->resource != NULL && resourceId == entry->resourceId)
        {
            resourceHandle = (ExpgfxResourceHandle*)EXPGFX_RUNTIME_DATA->resourceTable[i].resource;
            if (resourceHandle != NULL &&
                resourceHandle->refCount >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT)
            {
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            EXPGFX_RUNTIME_DATA->resourceTable[i].evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
            return (s16)i;
        }
    }
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++)
    {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->resource == NULL)
        {
            EXPGFX_RUNTIME_DATA->resourceTable[i].resource = textureLoadAsset(resourceId);
            resourceHandle = (ExpgfxResourceHandle*)EXPGFX_RUNTIME_DATA->resourceTable[i].resource;
            if (resourceHandle != NULL &&
                resourceHandle->refCount >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT)
            {
                gExpgfxTextureFreeInProgress = 1;
                if (resourceHandle != NULL)
                {
                    textureFree((u8*)resourceHandle);
                }
                gExpgfxTextureFreeInProgress = 0;
                entry->resource = NULL;
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            if (resourceHandle != NULL)
            {
                entry->evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
                entry->resourceId = resourceId;
                return (s16)i;
            }
            return EXPGFX_RESOURCE_ACQUIRE_LOAD_FAILED;
        }
    }
    if ((u8)Obj_IsLoadingLocked() == 0)
    {
        return EXPGFX_RESOURCE_ACQUIRE_LOADING_UNLOCKED;
    }
    minEvictionScore = EXPGFX_RESOURCE_EVICTION_SCAN_INITIAL;
    minIndex = 0;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++)
    {
        entry = &EXPGFX_RUNTIME_DATA->resourceTable[i];
        if (entry->evictionScore < minEvictionScore)
        {
            minEvictionScore = entry->evictionScore;
            minIndex = i;
        }
    }
    entry = &EXPGFX_RUNTIME_DATA->resourceTable[minIndex];
    gExpgfxTextureFreeInProgress = 1;
    resourceHandle = (ExpgfxResourceHandle*)entry->resource;
    if (resourceHandle != NULL)
    {
        textureFree((u8*)resourceHandle);
    }
    gExpgfxTextureFreeInProgress = 0;
    entry->resource = NULL;
    entry->resource = textureLoadAsset(resourceId);
    if (entry->resource != NULL)
    {
        entry->evictionScore = EXPGFX_RESOURCE_EVICTION_RESET;
        entry->resourceId = resourceId;
        return (s16)minIndex;
    }
    return EXPGFX_RESOURCE_ACQUIRE_RELOAD_FAILED;
}

