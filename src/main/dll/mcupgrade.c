#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
int mcupgradema_SeqFn(int p1, int p2, int setup)
{
    int i;
    for (i = 0; i < *(u8 *)(setup + 0x8b); i++) {
        switch (*(u8 *)(setup + 0x81 + i)) {
        case 0:
            hudFn_8011f38c(1);
            break;
        case 1:
            fn_80296A9C(Obj_GetPlayerObject(), 0x19);
            (*(void (**)(int, int, int, int))(*gGameUIInterface + 0x38))(0x468, 0x14, 0x8c, 0);
            break;
        case 2:
            hudFn_8011f38c(0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcupgrade_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1e), 1);
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcupgrade_init(int obj) { *(int *)(obj + 0xbc) = (int)mcupgrade_SeqFn; }
#pragma scheduling reset
#pragma peephole reset
