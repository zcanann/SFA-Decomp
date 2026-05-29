#include "main/dll/DR/dr_shared.h"

int drgenerator_getExtraSize(void) { return 0x19c; }

int drgenerator_getObjectTypeId(void) { return 0x0; }

void drgenerator_initialise(void) {}

void drgenerator_release(void) {}

#pragma scheduling off
#pragma peephole off
void drgenerator_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x3);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drgenerator_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6B58);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drgenerator_eventCallback(int obj, int unused, u8 *arg) {
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1) {
            int *t = objFindTexture(obj, 0, 0);
            if (t != 0) {
                *t = 0;
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drgenerator_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 fv;
    if (*(s16 *)((char *)obj + 0x46) == 0x72e) {
        int *t;
        *(void **)((char *)obj + 0xbc) = (void *)drgenerator_eventCallback;
        t = objFindTexture(obj, 0, 0);
        if (t != 0) {
            *t = 0x100;
        }
    }
    *(u8 *)(p + 0x19a) = 2;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, 0x3);
    *(int *)p = 0;
    ((BitFlags8 *)(p + 0x19b))->b3 = 1;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(s16 *)(p + 0x198) = (*(s16 *)(arg + 0x1a) == 0) ? 0x14 : *(s16 *)(arg + 0x1a);
    *(s16 *)(p + 0x198) = *(s16 *)(p + 0x198) * 0x3c;
    *(f32 *)(p + 0x124) = lbl_803E6B68;
    if (GameBit_Get(0x9b9) != 0) {
        ((BitFlags8 *)(p + 0x19b))->b0 = 1;
        ((BitFlags8 *)(p + 0x19b))->b4 = 1;
    } else {
        ((BitFlags8 *)(p + 0x19b))->b4 = 0;
    }
    fv = lbl_803E6B6C;
    *(f32 *)((char *)obj + 0x2c) = fv;
    *(f32 *)((char *)obj + 0x28) = fv;
    *(f32 *)((char *)obj + 0x24) = fv;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drgenerator_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    f32 a18;
    f32 a14;
    f32 a10;
    int ac;
    int a8;
    void *found;
    if (((BitFlags8 *)(p + 0x19b))->b0 || ((BitFlags8 *)(p + 0x19b))->b3) {
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition(obj, &a8, 0, &ac, &a10, &a14, &a18) != 5) {
        return;
    }
    p[0x19a] = p[0x19a] - ac;
    fn_80221E94(obj, &a10, lbl_803E6B5C);
    fn_8009A8C8(obj, lbl_803E6B60);
    if (p[0x19a] > 0) {
        return;
    }
    {
        int *tex = objFindTexture(obj, 0, 0);
        spawnExplosion(obj, lbl_803E6B64, 1, 1, 1, 1, 0, 1, 0);
        if (tex != 0) {
            *tex = 0x100;
        }
    }
    ((BitFlags8 *)(p + 0x19b))->b0 = 1;
    GameBit_Set(*(s16 *)(q + 0x1e), 1);
    if (*(s16 *)((char *)obj + 0x46) == 0x716 &&
        (found = (void *)ObjGroup_FindNearestObject(0x4c, obj, 0)) != NULL) {
        timer_addDuration((int)found, *(s16 *)(p + 0x198));
    } else {
        ObjHits_DisableObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drgenerator_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int n;
    if (((BitFlags8 *)(p + 0x19b))->b4 == 0 && GameBit_Get(0x9b9) != 0) {
        ((BitFlags8 *)(p + 0x19b))->b4 = 1;
    }
    if (((BitFlags8 *)(p + 0x19b))->b4 != 0) {
        goto loop;
    }
    if (((BitFlags8 *)(p + 0x19b))->b3 != 0) {
        goto enable;
    }
    if (GameBit_Get(*(s16 *)(q + 0x20)) != 0) {
        goto enable;
    }
    if (*(s16 *)((char *)obj + 0x46) != 0x72e) {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(4, obj, -1);
    }
    ((BitFlags8 *)(p + 0x19b))->b3 = 1;
    ((BitFlags8 *)(p + 0x19b))->b0 = 0;
    ObjHits_DisableObject(obj);
    return;
enable:
    if (((BitFlags8 *)(p + 0x19b))->b3 == 0) {
        goto loop;
    }
    if (GameBit_Get(*(s16 *)(q + 0x20)) == 0) {
        goto loop;
    }
    if (*(s16 *)((char *)obj + 0x46) != 0x72e) {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(3, obj, -1);
    }
    ((BitFlags8 *)(p + 0x19b))->b3 = 0;
    ObjHits_EnableObject(obj);
    return;
loop:
    if (((BitFlags8 *)(p + 0x19b))->b0 == 0) {
        return;
    }
    n = 1;
    do {
        (*(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x690, 0, 1, -1, 0);
    } while (n-- != 0);
}
#pragma peephole reset
#pragma scheduling reset
