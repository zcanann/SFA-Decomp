#include "main/dll/DR/dr_shared.h"

void explodeplan_free(void) {}

int explodeplan_getExtraSize(void) { return 0x4; }

int explodeplan_getObjectTypeId(void) { return 0x0; }

void explodeplan_hitDetect(void) {}

void explodeplan_initialise(void) {}

void explodeplan_release(void) {}

#pragma scheduling off
#pragma peephole off
void explodeplan_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D8);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explodeplan_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)explodeplan_updateTriggerCallback;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b2 = 1;
        *(int *)p = 2;
    } else {
        *(int *)p = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void explodeplan_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    if (((BitFlags8 *)(p + 0x4))->b1 != 0) {
        return;
    }
    if (*(int *)p == 0 && GameBit_Get(*(s16 *)(q + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        *(int *)p = 2;
    }
    if (((BitFlags8 *)(p + 0x4))->b2 != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        (*(void (**)(int, int))((char *)*gObjectTriggerInterface + 0x54))(obj, 0x76c);
        if (GameBit_Get(0x9f3) != 0) {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, 0x60);
        } else {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, 0x70);
        }
    } else {
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(*(int *)p, obj, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int explodeplan_updateTriggerCallback(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *runtime = *(char **)((char *)obj + 0xb8);
    int ret;
    if (*(int *)runtime == 0) {
        if (GameBit_Get(*(s16 *)(q + 0x1e)) != 0) {
            Sfx_StopObjectChannel(obj, 8);
            return 4;
        }
        if (((BitFlags8 *)(runtime + 4))->b0 != GameBit_Get(*(s16 *)(q + 0x20))) {
            Sfx_PlayFromObject(obj, 402);
            Sfx_PlayFromObject(obj, 403);
            if (GameBit_Get(*(s16 *)(q + 0x20)) != 0) {
                Sfx_PlayFromObject(obj, 404);
            } else {
                Sfx_StopObjectChannel(obj, 8);
            }
        }
        ((BitFlags8 *)(runtime + 4))->b0 = GameBit_Get(*(s16 *)(q + 0x20));
    }
    ret = 0;
    if (*(int *)runtime == 0) {
        if (GameBit_Get(*(s16 *)(q + 0x20)) == 0) {
            ret = 1;
        }
    }
    return ret;
}
#pragma peephole reset
#pragma scheduling reset
