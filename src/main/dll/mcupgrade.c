#include "main/dll/dll_80220608_shared.h"
#include "main/dll/mcupgrade_state.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objseq.h"

int mcupgradema_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case MCUPGRADEMA_EVENT_SHOW_HUD:
            hudFn_8011f38c(1);
            break;
        case MCUPGRADEMA_EVENT_SHOW_DIALOGUE:
            fn_80296A9C(Obj_GetPlayerObject(), 0x19);
            (*gGameUIInterface)->showNpcDialogue(0x468, 0x14, 0x8c, 0);
            break;
        case MCUPGRADEMA_EVENT_HIDE_HUD:
            hudFn_8011f38c(0);
            break;
        }
    }
    return 0;
}

#pragma peephole on
void mcupgrade_update(int obj)
{
    GameObject *gameObj = (GameObject *)obj;
    McUpgradeSetup *setup = (McUpgradeSetup *)gameObj->anim.placementData;

    if ((u32)GameBit_Get(setup->collectedGameBit) != 0) {
        *(u8 *)&gameObj->anim.resetHitboxMode |= MCUPGRADE_OBJ_FLAG_COLLECTED;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(setup->collectedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}

void mcupgrade_init(int obj) { ((GameObject *)obj)->animEventCallback = (void *)mcupgrade_SeqFn; }
