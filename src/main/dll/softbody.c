#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling on
int softbody_getExtraSize(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int softbody_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void softbody_free(int obj)
{
    if ((void *)obj == lbl_803DDD98) {
        lbl_803DDD98 = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void softbody_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7288);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void softbody_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void softbody_init(int obj, int setup)
{
    ((GameObject *)obj)->anim.rotZ = (s16)(*(u8 *)(setup + 0x18) << 8);
    ((GameObject *)obj)->anim.rotY = (s16)(*(u8 *)(setup + 0x19) << 8);
    ((GameObject *)obj)->anim.rotX = (s16)(*(u8 *)(setup + 0x1a) << 8);
    if (*(u8 *)(setup + 0x1b) != 0) {
        ((GameObject *)obj)->anim.rootMotionScale = (f32)(u32)*(u8 *)(setup + 0x1b) / lbl_803E7294;
        if (((GameObject *)obj)->anim.rootMotionScale == lbl_803E7298) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E7288;
        }
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    }
    ((GameObject *)obj)->unkB0 |= 0x2000;
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E7298, 0);
    if (((GameObject *)obj)->anim.hitReactState != NULL) {
        ObjHitbox_SetSphereRadius(obj,
            (s16)((f32)*(s16 *)(*(int *)&((GameObject *)obj)->anim.hitReactState + 0x5a) * ((GameObject *)obj)->anim.rootMotionScale));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void softbody_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void softbody_initialise(void)
{
    lbl_803DDD98 = NULL;
    lbl_803DDDA0 = lbl_803E7298;
    lbl_803DDD9C = lbl_803E7298;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void softbody_update(int obj)
{
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;

    if (lbl_803DDD98 == NULL && *(u8 *)(setup + 0x1f) == 0) {
        lbl_803DDD98 = (void *)obj;
    }

    if ((void *)obj == lbl_803DDD98) {
        lbl_803DDDA0 = lbl_803E728C * timeDelta + lbl_803DDDA0;
        while (lbl_803DDDA0 > lbl_803E7288) {
            lbl_803DDDA0 -= lbl_803E7288;
        }
        lbl_803DDD9C = lbl_803E7290 * timeDelta + lbl_803DDD9C;
        while (lbl_803DDD9C > lbl_803E7288) {
            lbl_803DDD9C -= lbl_803E7288;
        }
    }

    if (((GameObject *)obj)->anim.seqId >= 0x6af && ((GameObject *)obj)->anim.seqId < 0x6b2) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDDA0, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDD9C, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset
