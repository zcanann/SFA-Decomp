#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int dll_2A4_getExtraSize_ret_12(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int dll_2A4_getObjectTypeId(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A4_free_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A4_hitDetect_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A4_release_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A4_initialise_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void dll_2A4_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7138);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A4_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(f32 *)state > lbl_803E713C) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= lbl_803E713C) {
            *(f32 *)state = lbl_803E713C;
            Obj_FreeObject(obj);
            return;
        }
    }

    *(s16 *)(obj + 0) = (s16)((f32) * (s16 *)(state + 4) * timeDelta + (f32) * (s16 *)(obj + 0));
    *(s16 *)(obj + 2) = (s16)((f32) * (s16 *)(state + 6) * timeDelta + (f32) * (s16 *)(obj + 2));
    *(s16 *)(obj + 4) = (s16)((f32) * (s16 *)(state + 8) * timeDelta + (f32) * (s16 *)(obj + 4));

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_2A4_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(obj + 0) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 2) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 4) = randomGetRange(0, 0xffff);
    *(s16 *)(state + 4) = randomGetRange(-0x14, 0x14);
    *(s16 *)(state + 6) = randomGetRange(-0x14, 0x14);
    *(s16 *)(state + 8) = randomGetRange(-0x14, 0x14);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_802315EC(int obj, int state, int setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x20, 0x616);
        *(f32 *)(newObj + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x22), (s8)*(u8 *)(setup + 0x22));
        *(f32 *)(newObj + 0xc) = *(f32 *)(obj + 0x10) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x23), (s8)*(u8 *)(setup + 0x23));
        *(f32 *)(newObj + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x24), (s8)*(u8 *)(setup + 0x24));
        *(u8 *)(newObj + 0x1a) = 0;
        *(u8 *)(newObj + 0x19) = 0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)(s8)*(u8 *)(setup + 0x1c) / lbl_803E7140;
        dir[1] = (f32)(s8)*(u8 *)(setup + 0x1d) / lbl_803E7140;
        dir[2] = (f32)(s8)*(u8 *)(setup + 0x1e) / lbl_803E7140;
        fn_8023137C(newObj, (int)dir);
        fn_8023134C(newObj, *(u16 *)(setup + 0x1a));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_802317A8(int obj, int state, int setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x20, 0x617);
        *(f32 *)(newObj + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x22), (s8)*(u8 *)(setup + 0x22));
        *(f32 *)(newObj + 0xc) = *(f32 *)(obj + 0x10) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x23), (s8)*(u8 *)(setup + 0x23));
        *(f32 *)(newObj + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x24), (s8)*(u8 *)(setup + 0x24));
        *(u8 *)(newObj + 0x1a) = 0;
        *(u8 *)(newObj + 0x19) = 0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)(s8)*(u8 *)(setup + 0x1c) / lbl_803E7140;
        dir[1] = (f32)(s8)*(u8 *)(setup + 0x1d) / lbl_803E7140;
        dir[2] = (f32)(s8)*(u8 *)(setup + 0x1e) / lbl_803E7140;
        fn_80231058(newObj, (int)dir);
        fn_80231028(newObj, *(u16 *)(setup + 0x1a));
    }
}
#pragma scheduling reset
#pragma peephole reset
