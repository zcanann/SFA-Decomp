#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

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
            (*gGameUIInterface)->showNpcDialogue(0x468, 0x14, 0x8c, 0);
            break;
        case 2:
            hudFn_8011f38c(0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset

#pragma scheduling off
void mcupgrade_update(int obj)
{
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1e), 1);
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}
#pragma scheduling reset

#pragma scheduling off
void mcupgrade_init(int obj) { ((GameObject *)obj)->animEventCallback = (void *)mcupgrade_SeqFn; }
#pragma scheduling reset
