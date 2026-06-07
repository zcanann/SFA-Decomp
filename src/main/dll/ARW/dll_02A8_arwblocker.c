#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

#pragma scheduling off
int arwblocker_getBlockState(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    switch (*(u8 *)(state + 0)) {
    case 1:
        if (*(u8 *)(state + 1) != 0) {
            break;
        }
        return 1;
    case 0:
        break;
    }
    return 0;
}
#pragma scheduling reset

#pragma peephole on
#pragma scheduling on
int arwblocker_getExtraSize(void) { return 2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwblocker_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwblocker_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwblocker_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwblocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7218);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwblocker_init(int obj, int setup)
{
    ObjAnimComponent *objAnim = &((GameObject *)obj)->anim;
    int state = *(int *)&((GameObject *)obj)->extra;

    ((GameObject *)obj)->anim.rotX = -0x8000;
    ((GameObject *)obj)->anim.rotZ = (s16)(*(s8 *)(setup + 0x18) << 8);
    ((GameObject *)obj)->animEventCallback = (void *)arwblocker_getBlockState;
    *(u8 *)(state + 0) = *(u8 *)(setup + 0x19);
    ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
    ObjHits_DisableObject(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwblocker_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwblocker_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void arwblocker_update(int obj) {
    ObjAnimComponent *objAnim = &((GameObject *)obj)->anim;
    int state = *(int *)&((GameObject *)obj)->extra;
    int arwing = getArwing();

    if (arwing == 0)
        arwing = Obj_GetPlayerObject();
    if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E721C) {
        int a = (int)(lbl_803E7220 * timeDelta + (f32)(u32)objAnim->alpha);
        if (a > 0xff)
            a = 0xff;
        objAnim->alpha = a;
        ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        if (((GameObject *)obj)->unkF4 == 0) {
            switch (*(u8 *)(state + 0)) {
            case 1:
                ((ObjectTriggerInterface *)*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
                break;
            case 0:
            default:
                ((ObjectTriggerInterface *)*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
                break;
            }
            ((GameObject *)obj)->unkF4 = 1;
        }
    }
}
#pragma scheduling reset
