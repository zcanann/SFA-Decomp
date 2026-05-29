#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

#pragma scheduling off
#pragma peephole off
void fn_8009AD44(void) {
    int *e;
    int i;

    i = 0;
    e = gExpgfxRuntimeData;
    for (; i < 0x20; i++) {
        if (e[2] != 0) {
            e[1] = e[1] - framesThisStep;
            if (e[1] <= 0) {
                e[2] = 0;
                e[1] = 0;
                e[3] = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree(e[0]);
                gExpgfxTextureFreeInProgress = 0;
                e[0] = 0;
            }
        }
        e += 4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int expgfx_acquireResourceEntry(int arg) {
    int minVal;
    int minIdx;
    int i;
    int *p;
    int *base;
    void *tex;

    i = 0;
    base = gExpgfxRuntimeData;
    p = base;
    for (; i < 0x20; i++) {
        if (*(void **)p != NULL && arg == p[2]) {
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= 0x4000) {
                return -1;
            }
            gExpgfxRuntimeData[i * 4 + 1] = 1000;
            return (s16)i;
        }
        p += 4;
    }
    p = base;
    for (i = 0; i < 0x20; i++) {
        if (*(void **)p == NULL) {
            gExpgfxRuntimeData[i * 4] = textureLoadAsset(arg);
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= 0x4000) {
                gExpgfxTextureFreeInProgress = 1;
                if (tex != NULL) {
                    textureFree((int)tex);
                }
                gExpgfxTextureFreeInProgress = 0;
                gExpgfxRuntimeData[i * 4] = 0;
                return -1;
            }
            if (tex != NULL) {
                gExpgfxRuntimeData[i * 4 + 1] = 1000;
                gExpgfxRuntimeData[i * 4 + 2] = arg;
                return (s16)i;
            }
            return -2;
        }
        p += 4;
    }
    if (Obj_IsLoadingLocked() == 0) {
        return -4;
    }
    minVal = 0xfa00;
    minIdx = 0;
    p = base;
    for (i = 0; i < 0x20; i++) {
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
    gExpgfxRuntimeData[minIdx * 4] = textureLoadAsset(arg);
    if (*(void **)&gExpgfxRuntimeData[minIdx * 4] != NULL) {
        gExpgfxRuntimeData[minIdx * 4 + 1] = 1000;
        gExpgfxRuntimeData[minIdx * 4 + 2] = arg;
        return (s16)minIdx;
    }
    return -3;
}
#pragma peephole reset
#pragma scheduling reset

