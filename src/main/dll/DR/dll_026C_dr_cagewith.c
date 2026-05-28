#include "main/dll/DR/dll_80211C24_shared.h"

int drcagewith_getExtraSize(void) { return 0x34; }

int drcagewith_getObjectTypeId(void) { return 0x0; }

void drcagewith_initialise(void) {}

void drcagewith_release(void) {}

void drcagewith_update(void) {}

#pragma scheduling off
#pragma peephole off
void drcagewith_hitDetect(int obj) {
    int *q = *(int **)((char *)obj + 0x4c);
    u8 *p;
    BitFlags8 *bf31;
    f32 maxDist;
    int i;
    int spawned;
    int *nearest;
    f32 v;
    f32 clamped;
    f32 px;
    f32 div;

    maxDist = lbl_803E69F4;
    p = *(u8 **)((char *)obj + 0xb8);
    bf31 = (BitFlags8 *)(p + 0x31);

    if (bf31->b1 != 0) {
        objParticleFn_80099d84(obj, lbl_803E69F8, 6, lbl_803E69F0, 0);
    }

    if (*(s16 *)((char *)obj + 0x46) == 2154 || *(s16 *)((char *)obj + 0x46) == 2155) {
        if (GameBit_Get(1545) != 0) {
            *(s16 *)((char *)obj + 6) &= ~0x4000;
        }
        return;
    }
    if (*(void **)p == NULL) {
        if (Obj_IsLoadingLocked()) {
            spawned = Obj_AllocObjectSetup(32, 1143);
            *(u8 *)(spawned + 4) = 2;
            *(u8 *)(spawned + 5) = 1;
            *(u8 *)(spawned + 5) = (u8)(*(u8 *)(spawned + 5) | (*(u8 *)((char *)q + 5) & 0x18));
            *(f32 *)(spawned + 8) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(spawned + 0xc) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(spawned + 0x10) = *(f32 *)((char *)obj + 0x14);
            spawned = Obj_SetupObject(spawned, 5, *(s8 *)((char *)obj + 0xac), -1,
                                      *(int *)((char *)obj + 0x30));
            *(s16 *)(spawned + 6) |= 0x4000;
            *(int *)(spawned + 0xf4) = 1;
            *(int *)p = spawned;
            return;
        }
    }
    if (bf31->b0 == 0) {
        if (GameBit_Get(1545) != 0) {
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 6) |= 0x4000;
            bf31->b0 = 1;
            nearest = (int *)ObjGroup_FindNearestObject(10, obj, &maxDist);
            if (nearest != NULL && *(s16 *)((char *)nearest + 0x46) == 1049) {
                *(int *)((char *)nearest + 0xf4) = 0;
                *(int *)(p + 4) = 0;
            }
            return;
        }
        v = oneOverTimeDelta * (*(f32 *)((char *)obj + 0xc) - *(f32 *)((char *)obj + 0x80)) * lbl_803E69FC;
        v = interpolate(v - *(f32 *)(p + 0x24), lbl_803E6A00, timeDelta);
        clamped = lbl_803E6A04 * timeDelta;
        if (v >= clamped) {
            clamped = lbl_803E6A08 * timeDelta;
            if (v <= clamped) {
                clamped = v;
            }
        }
        *(f32 *)(p + 0x24) = *(f32 *)(p + 0x24) + clamped;
        div = lbl_803E6A0C;
        for (i = 0; i < 9; i++) {
            nearest = objModelGetVecFn_800395d8(obj, i);
            if (nearest != NULL) {
                *(s16 *)((char *)nearest + 4) = (int)(*(f32 *)(p + 0x24) / div);
            }
        }
        if (*(void **)p != NULL) {
            *(s16 *)(*(int *)p + 4) = (int)*(f32 *)(p + 0x24);
            nearest = (int *)ObjGroup_FindNearestObject(10, obj, &maxDist);
            if (nearest != NULL && *(s16 *)((char *)nearest + 0x46) == 1049) {
                *(int *)((char *)nearest + 0xf4) = 1;
                *(int *)(p + 4) = (int)nearest;
                *(s16 *)((char *)nearest + 4) = *(s16 *)(*(int *)p + 4);
                *(int *)(*(int *)p + 0xf4) = 1;
            }
            if (*(void **)(p + 4) != NULL && (*(u16 *)(*(int *)(p + 4) + 0xb0) & 0x40) != 0) {
                *(int *)(p + 4) = 0;
            }
        }
    }
    if (bf31->b0 == 0) {
        if (GameBit_Get(3175) != 0) {
            px = *(f32 *)((char *)obj + 0xc);
            if (px >= lbl_803E6A10 && px <= lbl_803E6A14) {
                GameBit_Set(*(s16 *)((char *)q + 0x1e), 1);
            } else {
                GameBit_Set(3748, 1);
            }
        } else {
            GameBit_Set(3748, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drcagewith_setScale(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return p[0x30];
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drcagewith_free(int obj, int arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    char *x = *(char **)p;
    if (x != 0 && arg == 0 && *(void **)(x + 0x50) != 0) {
        char *y = *(char **)(p + 0x4);
        if (y != 0) {
            *(int *)(y + 0xf4) = 0;
        }
        *(int *)(*(char **)p + 0xf4) = 0;
        Obj_FreeObject(*(int *)p);
    }
    ObjGroup_RemoveObject(obj, 0x18);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drcagewith_toggleRopeStateCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1) {
            ((BitFlags8 *)(p + 0x31))->b1 ^= 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drcagewith_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    int *b;
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69F0);
        if (*(int **)p != 0) {
            ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(*(int *)p + 0xc), (f32 *)(*(int *)p + 0x10), (f32 *)(*(int *)p + 0x14), 0);
            objRenderFn_8003b8f4(*(void **)p, p2, p3, p4, p5, (double)lbl_803E69F0);
            b = *(int **)(p + 0x4);
            if (b != 0) {
                *(s16 *)((char *)b + 0x2) = *(s16 *)(*(int *)p + 0x2);
                *(s16 *)((char *)b + 0x4) = *(s16 *)(*(int *)p + 0x4);
                ObjPath_GetPointWorldPosition(*(int *)p, 0, (f32 *)((char *)b + 0xc), (f32 *)((char *)b + 0x10), (f32 *)((char *)b + 0x14), 0);
                objRenderFn_8003b8f4(b, p2, p3, p4, p5, (double)lbl_803E69F0);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drcagewith_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    s16 type;
    f32 fz;
    *(void **)((char *)obj + 0xbc) = (void *)drcagewith_toggleRopeStateCallback;
    type = *(s16 *)((char *)obj + 0x46);
    if (type == 0x86a || type == 0x86b) {
        if (GameBit_Get(0x609) == 0) {
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    } else {
        ObjHits_EnableObject(obj);
        if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
            ((BitFlags8 *)(p + 0x31))->b0 = 1;
        } else {
            GameBit_Set(0x7aa, 5);
        }
        *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
        *(f32 *)(p + 0x8) = (f32)*(s16 *)(arg + 0x1c);
        *(f32 *)(p + 0x10) = (f32)*(s16 *)(arg + 0x1a) / lbl_803E6A18;
        *(int *)(p + 0x4) = 0;
        fz = lbl_803E6A1C;
        *(f32 *)(p + 0x14) = fz;
        *(f32 *)(p + 0x18) = fz;
        *(f32 *)(p + 0x1c) = fz;
        *(f32 *)(p + 0x20) = fz;
        ObjGroup_AddObject(obj, 0x18);
    }
}
#pragma peephole reset
#pragma scheduling reset
