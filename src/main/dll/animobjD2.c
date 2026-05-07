#include "ghidra_import.h"
#include "main/dll/animobjD2.h"

#pragma peephole off
#pragma scheduling off

extern void *fn_80296118(void *p);
extern void **ObjGroup_GetObjects(int group, int *countOut);
extern f32 Vec_xzDistance(void *a, void *b);

extern f32 lbl_803E23F8;

void *fn_8013EE84(void *obj, void *arg2) {
    void *p_24 = *(void **)((u8 *)arg2 + 0x24);
    void *target;
    void **list;
    int count;
    int i;
    f32 d1, d2, d3;

    if (*(s16 *)((u8 *)p_24 + 0x46) == 0x6a3) {
        return p_24;
    }

    target = fn_80296118(*(void **)((u8 *)arg2 + 0x4));
    if (target == NULL) goto fail;

    list = ObjGroup_GetObjects(3, &count);
    for (i = 0; i < count; i++) {
        if (list[i] == target) {
            d1 = Vec_xzDistance((u8 *)obj + 0x18, (u8 *)target + 0x18);
            d2 = Vec_xzDistance((u8 *)obj + 0x18, (u8 *)*(void **)((u8 *)arg2 + 0x4) + 0x18);
            d3 = Vec_xzDistance((u8 *)target + 0x18, (u8 *)*(void **)((u8 *)arg2 + 0x4) + 0x18);
            if ((d1 + d2) >= lbl_803E23F8 * d3) {
                goto fail;
            }
            return target;
        }
    }
fail:
    return NULL;
}
