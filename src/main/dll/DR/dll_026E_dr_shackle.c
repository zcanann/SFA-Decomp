#include "main/dll/DR/dr_shared.h"

#define SFXfoot_stone_run_1 0x1B3

int drshackle_getExtraSize(void) { return 0x20; }

int drshackle_getObjectTypeId(void) { return 0x0; }

void drshackle_release(void) {}

void drshackle_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int drshackle_setScale(int obj, int a, int b, int c, int d, int e, int f) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    int *q = *(int **)((char *)obj + 0x4c);
    int *model;
    int *modelData;
    s8 joint1;
    f32 jointPos[3];
    f32 parentPos[3];
    int i;
    int *ptr;
    BitFlags8 *bf = (BitFlags8 *)(p + 0x1a);

    if (bf->b0 == 0) {
        return 1;
    }
    *(f32 *)(p + 8) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)(p + 0xc) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)(p + 0x10) = *(f32 *)((char *)obj + 0x14);

    joint1 = *(s8 *)(*(int *)(*(int *)((char *)a + 0x50) + 0x2c) + b * 24 + *(s8 *)((char *)obj + 0xad) + 0x12);
    model = *(int **)(*(int *)((char *)a + 0x7c) + *(s8 *)((char *)a + 0xad) * 4);
    modelData = *(int **)model;

    *(s16 *)((char *)obj + 4) = 0;
    *(s16 *)((char *)obj + 2) = 0;
    ObjModel_CopyJointTranslation(model, joint1, jointPos);
    ObjModel_CopyJointTranslation(model, *(s8 *)(*(int *)((char *)modelData + 0x3c) + joint1 * 28),
                                  parentPos);
    PSVECSubtract(parentPos, jointPos, jointPos);

    if (*(s16 *)((char *)q + 0x1c) != 0) {
        *(s16 *)((char *)obj + 4) =
            (s16)((*(s16 *)((char *)q + 0x1c) << 14) + getAngle(jointPos[2], jointPos[0]));
        *(s16 *)((char *)obj + 2) = (s16)getAngle(jointPos[2], jointPos[1]);
    } else {
        f32 savedY = jointPos[1];
        f32 mag;
        jointPos[1] = lbl_803E6A28;
        mag = PSVECMag(jointPos);
        *(s16 *)((char *)obj + 4) = (s16)(lbl_803DC2F0 + getAngle(jointPos[0], jointPos[2]));
        *(s16 *)((char *)obj + 2) = (s16)(lbl_803DDD70 + getAngle(mag, savedY));
        objSetMtxFn_800412d4(ObjPath_GetPointModelMtx(a, b));
    }
    ObjPath_GetPointWorldPosition(a, b, (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x10),
                                  (f32 *)((char *)obj + 0x14), 0);
    objRenderFn_8003b8f4((void *)obj, c, d, e, f, (double)lbl_803E6A2C);

    ptr = (int *)p;
    for (i = 0; i < *(int *)(p + 0x14); i++) {
        int entry = *ptr;
        if (entry != 0) {
            ObjPath_GetPointWorldPosition(obj, p[i + 0x1b], (f32 *)(entry + 0xc),
                                          (f32 *)(entry + 0x10), (f32 *)(entry + 0x14), 0);
        }
        ptr++;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drshackle_func0B(int obj) {
    int p = *(int *)((char *)obj + 0x4c);
    return *(s8 *)(p + 0x19);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drshackle_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x37);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drshackle_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    ObjGroup_AddObject(obj, 0x37);
    ((BitFlags8 *)(p + 0x1a))->b0 = (GameBit_Get(*(s16 *)(arg + 0x1e)) == 0);
    *(u8 *)(p + 0x1b) = (s8)arg[0x18] % 2;
    *(void **)((char *)obj + 0xbc) = (void *)drshackle_toggleEventCallback;
    if (*(s16 *)(arg + 0x1c) == 1) {
        *(int *)(p + 0x14) = 2;
        *(u8 *)(p + 0x1c) = 1 - *(u8 *)(p + 0x1b);
    } else {
        *(int *)(p + 0x14) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drshackle_toggleEventCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *q = *(void **)p;
    int i;
    if (q != 0) {
        *(f32 *)((char *)q + 0xc) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)q + 0x10) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)q + 0x14) = *(f32 *)((char *)obj + 0x14);
    }
    for (i = 0; i < arg[0x8b]; i++) {
        switch (arg[i + 0x81]) {
        case 1:
            ((BitFlags8 *)(p + 0x1a))->b0 = 0;
            break;
        case 2:
            ((BitFlags8 *)(p + 0x1a))->b0 = 1;
            break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drshackle_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    int i;
    int *ptr;
    if (((BitFlags8 *)(p + 0x1a))->b0 == 0 && visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6A2C);
        ptr = (int *)p;
        for (i = 0; i < *(int *)(p + 0x14); i++) {
            int *entry = *(int **)ptr;
            if (entry != 0) {
                ObjPath_GetPointWorldPosition((int)obj, p[i + 0x1b], (f32 *)((char *)entry + 0xc), (f32 *)((char *)entry + 0x10), (f32 *)((char *)entry + 0x14), 0);
            }
            ptr++;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drshackle_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    int count;
    int *list;
    int j;
    if (*(s16 *)(q + 0x1a) != 0 && *(void **)p == 0) {
        list = ObjGroup_GetObjects(0x17, &count);
        while (count-- != 0) {
            int sub = *(int *)(*list + 0x4c);
            for (j = 0; j < *(int *)(p + 0x14); j++) {
                if (*(u8 *)(sub + 0x18) == *(s16 *)(q + 0x1a) + j * 4) {
                    *(int *)(p + j * 4) = *list;
                    (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(0, *(int *)(p + j * 4), -1);
                }
            }
            list++;
        }
    }
    if (((BitFlags8 *)(p + 0x1a))->b0 != 0) {
        ((BitFlags8 *)(p + 0x1a))->b0 = (GameBit_Get(*(s16 *)(q + 0x1e)) == 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drshackle_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (Sfx_IsPlayingFromObjectChannel(obj, 1) == 0 && ((BitFlags8 *)(p + 0x1a))->b0 != 0) {
        f32 vec[3];
        int n;
        PSVECSubtract((f32 *)((char *)obj + 0xc), (f32 *)(p + 0x8), vec);
        n = 0xc8 - (int)(lbl_803E6A30 * PSVECMag(vec));
        if (n < 1) {
            n = 1;
        } else if (n > 0xc8) {
            n = 0xc8;
        }
        if ((int)randomGetRange(0, n) == 0) {
            Sfx_PlayFromObject(obj, SFXfoot_stone_run_1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
