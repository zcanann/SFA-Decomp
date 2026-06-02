#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int androssbrain_getExtraSize(void) { return 0x28; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int androssbrain_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7600);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androssbrain_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    if (*(s8 *)(state + 0x1c) != 2 || force != 0) {
        *(s8 *)(state + 0x1c) = (s8)newState;
        if (force != 0) {
            *(u8 *)(state + 0x1e) = 0x50;
        }
    } else {
        andross_setPartSignal(*(int *)state, 1);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void androssbrain_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(state + 0x1e) = 0x50;
    ObjHits_SetTargetMask(obj, 4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androssbrain_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 flag = 0;
    int hitObj;
    int sphereIdx;
    int hitVol;
    int hit;
    int t;

    if (*(void **)state == NULL) {
        *(int *)state = ObjList_FindObjectById(0x47b77);
    }
    if (*(void **)(state + 4) == NULL) {
        *(int *)(state + 4) = ObjList_FindObjectById(0x4c611);
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);
    if (*(void **)state != NULL) {
        *(f32 *)(obj + 0xc) = *(f32 *)(*(int *)state + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(*(int *)state + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(*(int *)state + 0x14);
    }
    if (*(s8 *)(state + 0x1c) != *(s8 *)(state + 0x1d)) {
        flag = 1;
    }
    *(u8 *)(state + 0x1d) = *(u8 *)(state + 0x1c);
    switch (*(s8 *)(state + 0x1c)) {
    case 0:
        if (flag != 0) {
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        *(s16 *)obj = *(s16 *)(*(int *)state);
        *(s16 *)(obj + 6) |= 0x4000;
        break;
    case 1:
        if (flag != 0) {
            *(u8 *)(state + 0x1f) = 0x3c;
            (*(void (**)(int, int))(*gGameUIInterface + 0x58))(0x50, 0x643);
        }
        (*(void (**)(int))(*gGameUIInterface + 0x5c))(*(u8 *)(state + 0x1e));
        hit = ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol);
        t = *(u8 *)(state + 0x1f) - framesThisStep;
        if (t < 0) {
            t = 0;
        }
        *(u8 *)(state + 0x1f) = (u8)t;
        if (hit != 0) {
            if (*(u8 *)(state + 0x1f) == 0) {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                *(u8 *)(state + 0x1f) = 6;
                *(u8 *)(state + 0x1e) -= 1;
                if (*(u8 *)(state + 0x1e) == 0) {
                    *(u8 *)(state + 0x1c) = 2;
                    andross_setPartSignal(*(int *)state, 1);
                    Sfx_PlayFromObject(obj, 0x485);
                } else {
                    Sfx_PlayFromObject(obj, 0x484);
                }
            }
        }
        *(s16 *)(obj + 6) &= ~0x4000;
        break;
    case 2:
        if (flag != 0) {
            androssligh_setState(*(int *)(state + 4), 2, 0);
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        *(s16 *)(obj + 6) |= 0x4000;
        andross_setPartSignal(*(int *)state, 8);
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
