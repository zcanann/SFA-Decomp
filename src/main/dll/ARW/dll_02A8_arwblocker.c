#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
int arwblocker_getBlockState(int obj)
{
    int state = *(int *)(obj + 0xb8);
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
#pragma peephole reset

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
    int state = *(int *)(obj + 0xb8);
    *(s16 *)(obj + 0) = -0x8000;
    *(s16 *)(obj + 4) = (s16)(*(s8 *)(setup + 0x18) << 8);
    *(void **)(obj + 0xbc) = (void *)arwblocker_getBlockState;
    *(u8 *)(state + 0) = *(u8 *)(setup + 0x19);
    *(s16 *)(obj + 6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
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

#pragma peephole on
#pragma scheduling off
void arwblocker_update(int obj) {
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();
    if (arwing == 0)
        arwing = Obj_GetPlayerObject();
    if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E721C) {
        int a = (int)(lbl_803E7220 * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36));
        if (a > 0xff)
            a = 0xff;
        *(u8 *)(obj + 0x36) = a;
        *(s16 *)(obj + 6) &= ~0x4000;
        ObjHits_EnableObject(obj);
        if (*(int *)(obj + 0xf4) == 0) {
            switch (*(u8 *)(state + 0)) {
            case 1:
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                break;
            case 0:
            default:
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                break;
            }
            *(int *)(obj + 0xf4) = 1;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
