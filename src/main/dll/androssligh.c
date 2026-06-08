#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling on
int androssligh_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int androssligh_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssligh_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssligh_render(int obj)
{
    void *p = *(void **)(*(int *)&((GameObject *)obj)->extra + 4);

    if (p != NULL) {
        lightningRender(p);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void androssligh_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)&((GameObject *)obj)->extra;
    if (*(s8 *)(state + 0xc) == 2) {
        if (force == 0) {
            return;
        }
    }
    *(s8 *)(state + 0xc) = (s8)newState;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssligh_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssligh_init(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void androssligh_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    if (*(void **)state == NULL) {
        *(int *)state = ObjList_FindObjectById(0x47dd9);
    }
    if (*(void **)state != NULL) {
        ((GameObject *)obj)->anim.localPosX = *(f32 *)(*(int *)state + 0xc);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)(*(int *)state + 0x10);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)(*(int *)state + 0x14);
    }
    *(u8 *)(state + 0xd) = *(u8 *)(state + 0xc);
    switch (*(s8 *)(state + 0xc)) {
    case 0:
        break;
    case 1:
        androssligh_updateBeam(obj, state);
        break;
    case 2:
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void androssligh_updateBeam(int obj, int beam)
{
    f32 start[3];
    f32 end[3];
    f32 tmp[3];

    start[0] = ((GameObject *)obj)->anim.localPosX - lbl_803DC528;
    start[1] = ((GameObject *)obj)->anim.localPosY;
    start[2] = ((GameObject *)obj)->anim.localPosZ;
    end[0] = ((GameObject *)obj)->anim.localPosX + lbl_803DC528;
    end[1] = start[1];
    end[2] = start[2];
    tmp[0] = start[0] - playerMapOffsetX;
    tmp[1] = start[1];
    tmp[2] = start[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd((int)start, (int)tmp, (int)start);
    tmp[0] = end[0] - playerMapOffsetX;
    tmp[1] = end[1];
    tmp[2] = end[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd((int)end, (int)tmp, (int)end);
    if (*(void **)(beam + 4) == NULL) {
        *(int *)(beam + 4) = (int)lightningCreate(start, end, lbl_803DC518, lbl_803DC51C,
                                              (int)lbl_803DC520, (int)lbl_803DC524, 0);
        *(f32 *)(beam + 8) = lbl_803E7608;
    } else {
        *(f32 *)(beam + 8) += timeDelta;
        *(u16 *)(*(int *)(beam + 4) + 0x20) = (int)(lbl_803E760C + *(f32 *)(beam + 8));
        if (*(u16 *)(*(int *)(beam + 4) + 0x20) >= *(u16 *)(*(int *)(beam + 4) + 0x22)) {
            mm_free((void *)*(int *)(beam + 4));
            *(int *)(beam + 4) = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
