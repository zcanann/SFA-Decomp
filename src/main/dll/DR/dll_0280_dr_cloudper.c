#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int drcloudper_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drcloudper_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drcloudper_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x13);
    ObjGroup_RemoveObject(obj, 0x39);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_update(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int drcloudper_setScale(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) == 0) {
        return 0;
    }
    GameBit_Set(0x7a9, *(s8 *)(setup + 0x19));
    (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xc, 1);
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int drcloudper_selectActiveCloud(int obj)
{
    GameBit_Set(0x7a9, *(s8 *)(*(int *)(obj + 0x4c) + 0x19));
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drcloudper_init(int obj, int setup)
{
    int state;

    ObjGroup_AddObject(obj, 0x13);
    ObjGroup_AddObject(obj, 0x39);
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    state = *(int *)(obj + 0xb8);
    *(f32 *)(state + 0) = fn_80293E80(lbl_803E6BF0 * (f32) * (s16 *)obj / lbl_803E6BF4);
    *(f32 *)(state + 4) = lbl_803E6BF8;
    *(f32 *)(state + 8) = sin(lbl_803E6BF0 * (f32) * (s16 *)obj / lbl_803E6BF4);
    *(f32 *)(state + 0xc) =
        -(*(f32 *)(state + 8) * *(f32 *)(obj + 0x14)) +
        (*(f32 *)(state + 0) * *(f32 *)(obj + 0xc) + *(f32 *)(state + 4) * *(f32 *)(obj + 0x10));
    *(u16 *)(obj + 0xb0) |= 0xe000;
    if (*(s8 *)(setup + 0x19) == GameBit_Get(0x7a9)) {
        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xc, 1);
    }
}
#pragma scheduling reset
#pragma peephole reset
