#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int brokenpipe_getExtraSize(void) { return 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void brokenpipe_init(int obj, int setup)
{
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    if (*(u8 *)(setup + 0x1b) != 0) {
        *(f32 *)(obj + 8) = (f32)(u32)*(u8 *)(setup + 0x1b) / lbl_803E7338;
        if (*(f32 *)(obj + 8) == lbl_803E733C) {
            *(f32 *)(obj + 8) = lbl_803E7340;
        }
        ObjHitbox_SetSphereRadius(obj,
            (int)((f32)*(s16 *)(*(int *)(obj + 0x54) + 0x5a) * *(f32 *)(obj + 8)));
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    }
    *(u16 *)(obj + 0xb0) |= 0x4000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void brokenpipe_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
        *(int *)(obj + 0xb8));
}
#pragma scheduling reset
#pragma peephole reset
