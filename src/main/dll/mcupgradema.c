#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
int fn_802391C4(int p1, int p2, int setup)
{
    int staff;
    int i;

    if (Obj_GetPlayerObject() == 0) {
        return 0;
    }
    staff = fn_802966CC();
    if (staff == 0) {
        return 0;
    }
    for (i = 0; i < *(u8 *)(setup + 0x8b); i++) {
        switch (*(u8 *)(setup + 0x81 + i)) {
        case 1:
            staffSetGlow(staff, 5, 1);
            break;
        case 2:
            staffSetGlow(staff, 5, (u8)*(int *)(p1 + 0xf8));
            break;
        case 3:
            staffSetGlow(staff, 5, 0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcupgradema_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1a), 1);
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcupgradema_init(int obj) { *(int *)(obj + 0xbc) = (int)fn_80239054; }
#pragma scheduling reset
#pragma peephole reset
