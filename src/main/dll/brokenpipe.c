#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling on
int brokenpipe_getExtraSize(void) { return 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void brokenpipe_init(int obj, int setup)
{
    ((GameObject *)obj)->anim.rotZ = (s16)(*(u8 *)(setup + 0x18) << 8);
    ((GameObject *)obj)->anim.rotY = (s16)(*(u8 *)(setup + 0x19) << 8);
    ((GameObject *)obj)->anim.rotX = (s16)(*(u8 *)(setup + 0x1a) << 8);
    if (*(u8 *)(setup + 0x1b) != 0) {
        ((GameObject *)obj)->anim.rootMotionScale = (f32)(u32)*(u8 *)(setup + 0x1b) / lbl_803E7338;
        if (((GameObject *)obj)->anim.rootMotionScale == lbl_803E733C) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E7340;
        }
        ObjHitbox_SetSphereRadius(obj,
            (int)((f32)*(s16 *)(*(int *)&((GameObject *)obj)->anim.hitReactState + 0x5a) * ((GameObject *)obj)->anim.rootMotionScale));
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    }
    ((GameObject *)obj)->unkB0 |= 0x4000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void brokenpipe_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
        *(int *)&((GameObject *)obj)->extra);
}
#pragma scheduling reset
#pragma peephole reset
