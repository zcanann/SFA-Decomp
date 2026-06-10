#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

#include "main/audio/sfx_ids.h"

typedef struct ExplodeplanUpdateTriggerCallbackPlacement {
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} ExplodeplanUpdateTriggerCallbackPlacement;

void explodeplan_free(void) {}

int explodeplan_getExtraSize(void) { return 0x4; }

int explodeplan_getObjectTypeId(void) { return 0x0; }

void explodeplan_hitDetect(void) {}

void explodeplan_initialise(void) {}

void explodeplan_release(void) {}

void explodeplan_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D8);
    }
}

void explodeplan_init(int obj, char *arg) {
    char *p = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)explodeplan_updateTriggerCallback;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b2 = 1;
        *(int *)p = 2;
    } else {
        *(int *)p = 0;
    }
}

void explodeplan_update(int obj) {
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    char *p = ((GameObject *)obj)->extra;
    if (((BitFlags8 *)(p + 0x4))->b1 != 0) {
        return;
    }
    if (*(int *)p == 0 && GameBit_Get(*(s16 *)(q + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        *(int *)p = 2;
    }
    if (((BitFlags8 *)(p + 0x4))->b2 != 0) {
        ((BitFlags8 *)(p + 0x4))->b1 = 1;
        (*gObjectTriggerInterface)->preempt(obj, 0x76c);
        if (GameBit_Get(0x9f3) != 0) {
            (*gObjectTriggerInterface)->runSequence(*(int *)p, (void *)obj, 0x60);
        } else {
            (*gObjectTriggerInterface)->runSequence(*(int *)p, (void *)obj, 0x70);
        }
    } else {
        (*gObjectTriggerInterface)->runSequence(*(int *)p, (void *)obj, -1);
    }
}

int explodeplan_updateTriggerCallback(int obj) {
    int ret;
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    char *runtime = ((GameObject *)obj)->extra;
    if (*(int *)runtime == 0) {
        if (GameBit_Get(((ExplodeplanUpdateTriggerCallbackPlacement *)q)->unk1E) != 0) {
            Sfx_StopObjectChannel(obj, 8);
            return 4;
        }
        if (((BitFlags8 *)(runtime + 4))->b0 != GameBit_Get(((ExplodeplanUpdateTriggerCallbackPlacement *)q)->unk20)) {
            Sfx_PlayFromObject(obj, SFXar_ring_pickup);
            Sfx_PlayFromObject(obj, SFXar_generic_pickup);
            if (GameBit_Get(((ExplodeplanUpdateTriggerCallbackPlacement *)q)->unk20) != 0) {
                Sfx_PlayFromObject(obj, SFXar_bomb_pickup);
            } else {
                Sfx_StopObjectChannel(obj, 8);
            }
        }
        ((BitFlags8 *)(runtime + 4))->b0 = GameBit_Get(((ExplodeplanUpdateTriggerCallbackPlacement *)q)->unk20);
    }
    ret = 0;
    if (*(int *)runtime == 0) {
        if (GameBit_Get(((ExplodeplanUpdateTriggerCallbackPlacement *)q)->unk20) == 0) {
            ret = 1;
        }
    }
    return ret;
}
