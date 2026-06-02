#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/expgfx_internal.h"

#define EXPGFX_RESOURCE_ENTRY_WORD_COUNT (sizeof(ExpgfxResourceEntry) / sizeof(int))

#pragma scheduling off
#pragma peephole off
void expgfx_updateResourceEntries(int unused) {
    ExpgfxResourceEntry *entry;
    int i;

    i = 0;
    entry = EXPGFX_RUNTIME_DATA->resourceTable;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (entry->resourceId != 0) {
            entry->evictionScore = entry->evictionScore - framesThisStep;
            if (entry->evictionScore <= 0) {
                entry->resourceId = 0;
                entry->evictionScore = 0;
                entry->wordC = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree((int)entry->resource);
                gExpgfxTextureFreeInProgress = 0;
                entry->resource = NULL;
            }
        }
        entry++;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int expgfx_acquireResourceEntry(int resourceId) {
    int minEvictionScore;
    int minIndex;
    int i;
    int *entryWords;
    int *resourceTableWords;
    void *texture;

    i = 0;
    resourceTableWords = gExpgfxRuntimeData;
    entryWords = resourceTableWords;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (*(void **)entryWords != NULL && resourceId == entryWords[2]) {
            texture = *(void **)&gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT];
            if (texture != NULL && *(u16 *)((char *)texture + EXPGFX_RESOURCE_HANDLE_REFCOUNT_OFFSET) >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
            return (s16)i;
        }
        entryWords += EXPGFX_RESOURCE_ENTRY_WORD_COUNT;
    }
    entryWords = resourceTableWords;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (*(void **)entryWords == NULL) {
            gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT] = textureLoadAsset(resourceId);
            texture = *(void **)&gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT];
            if (texture != NULL && *(u16 *)((char *)texture + EXPGFX_RESOURCE_HANDLE_REFCOUNT_OFFSET) >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                gExpgfxTextureFreeInProgress = 1;
                if (texture != NULL) {
                    textureFree((int)texture);
                }
                gExpgfxTextureFreeInProgress = 0;
                gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT] = 0;
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            if (texture != NULL) {
                gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
                gExpgfxRuntimeData[i * EXPGFX_RESOURCE_ENTRY_WORD_COUNT + 2] = resourceId;
                return (s16)i;
            }
            return EXPGFX_RESOURCE_ACQUIRE_LOAD_FAILED;
        }
        entryWords += EXPGFX_RESOURCE_ENTRY_WORD_COUNT;
    }
    if (Obj_IsLoadingLocked() == 0) {
        return EXPGFX_RESOURCE_ACQUIRE_LOADING_UNLOCKED;
    }
    minEvictionScore = EXPGFX_RESOURCE_EVICTION_SCAN_INITIAL;
    minIndex = 0;
    entryWords = resourceTableWords;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (entryWords[1] < minEvictionScore) {
            minEvictionScore = entryWords[1];
            minIndex = i;
        }
        entryWords += EXPGFX_RESOURCE_ENTRY_WORD_COUNT;
    }
    gExpgfxTextureFreeInProgress = 1;
    texture = *(void **)&gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT];
    if (texture != NULL) {
        textureFree((int)texture);
    }
    gExpgfxTextureFreeInProgress = 0;
    gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT] = 0;
    gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT] = textureLoadAsset(resourceId);
    if (*(void **)&gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT] != NULL) {
        gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
        gExpgfxRuntimeData[minIndex * EXPGFX_RESOURCE_ENTRY_WORD_COUNT + 2] = resourceId;
        return (s16)minIndex;
    }
    return EXPGFX_RESOURCE_ACQUIRE_RELOAD_FAILED;
}
#pragma peephole reset
#pragma scheduling reset

