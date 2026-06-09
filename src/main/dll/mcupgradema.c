#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

#pragma scheduling off
int mcstaffeffe_SeqFn(int p1, int p2, int setup)
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

#pragma scheduling off
void mcupgradema_update(int obj)
{
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1a), 1);
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}
#pragma scheduling reset

#pragma scheduling off
void mcupgradema_init(int obj) { ((GameObject *)obj)->animEventCallback = (void *)mcupgradema_SeqFn; }
#pragma scheduling reset
