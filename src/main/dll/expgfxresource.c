#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/expgfx_internal.h"

#pragma scheduling off
#pragma peephole off
void expgfx_updateResourceEntries(int unused) {
    ExpgfxResourceEntry *entry;
    int i;

    i = 0;
    entry = EXPGFX_RUNTIME_DATA->resourceTable;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (entry->tableKeyType != 0) {
            entry->evictionScore = entry->evictionScore - framesThisStep;
            if (entry->evictionScore <= 0) {
                entry->tableKeyType = 0;
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
    int minVal;
    int minIdx;
    int i;
    int *p;
    int *base;
    void *tex;

    i = 0;
    base = gExpgfxRuntimeData;
    p = base;
    for (; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (*(void **)p != NULL && resourceId == p[2]) {
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            gExpgfxRuntimeData[i * 4 + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
            return (s16)i;
        }
        p += 4;
    }
    p = base;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (*(void **)p == NULL) {
            gExpgfxRuntimeData[i * 4] = textureLoadAsset(resourceId);
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= EXPGFX_RESOURCE_TEXTURE_REFCOUNT_LIMIT) {
                gExpgfxTextureFreeInProgress = 1;
                if (tex != NULL) {
                    textureFree((int)tex);
                }
                gExpgfxTextureFreeInProgress = 0;
                gExpgfxRuntimeData[i * 4] = 0;
                return EXPGFX_RESOURCE_ACQUIRE_TEXTURE_BUSY;
            }
            if (tex != NULL) {
                gExpgfxRuntimeData[i * 4 + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
                gExpgfxRuntimeData[i * 4 + 2] = resourceId;
                return (s16)i;
            }
            return EXPGFX_RESOURCE_ACQUIRE_LOAD_FAILED;
        }
        p += 4;
    }
    if (Obj_IsLoadingLocked() == 0) {
        return EXPGFX_RESOURCE_ACQUIRE_LOADING_UNLOCKED;
    }
    minVal = EXPGFX_RESOURCE_EVICTION_SCAN_INITIAL;
    minIdx = 0;
    p = base;
    for (i = 0; i < EXPGFX_RESOURCE_TABLE_COUNT; i++) {
        if (p[1] < minVal) {
            minVal = p[1];
            minIdx = i;
        }
        p += 4;
    }
    gExpgfxTextureFreeInProgress = 1;
    tex = *(void **)&gExpgfxRuntimeData[minIdx * 4];
    if (tex != NULL) {
        textureFree((int)tex);
    }
    gExpgfxTextureFreeInProgress = 0;
    gExpgfxRuntimeData[minIdx * 4] = 0;
    gExpgfxRuntimeData[minIdx * 4] = textureLoadAsset(resourceId);
    if (*(void **)&gExpgfxRuntimeData[minIdx * 4] != NULL) {
        gExpgfxRuntimeData[minIdx * 4 + 1] = EXPGFX_RESOURCE_EVICTION_RESET;
        gExpgfxRuntimeData[minIdx * 4 + 2] = resourceId;
        return (s16)minIdx;
    }
    return EXPGFX_RESOURCE_ACQUIRE_RELOAD_FAILED;
}
#pragma peephole reset
#pragma scheduling reset

