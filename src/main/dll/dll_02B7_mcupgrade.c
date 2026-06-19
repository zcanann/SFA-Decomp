/*
 * mcupgrade (DLL 0x2B7) - a one-shot upgrade pickup object.
 *
 * mcupgrade_update gates the object on its placement's collectedGameBit:
 * once that bit is set the object is flagged collected; until then, an
 * object-trigger hit sets the bit and runs trigger sequence 0 (the
 * pickup sequence). The sequence drives the HUD and an NPC dialogue line
 * through mcupgrade's own SeqFn (mcupgradema_SeqFn): show HUD, show NPC
 * dialogue 0x468, hide HUD.
 *
 * mcupgrade_init wires the object's anim event callback to mcupgrade_SeqFn,
 * which lives in the cnthitobjec TU (DLL 0x2B6). Sibling object mcupgradema
 * lives in DLL 0x2B8.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/mcupgrade_state.h"
#include "main/game_object.h"

int mcupgradema_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
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

void mcupgrade_update(int obj)
{
    GameObject* gameObj = (GameObject*)obj;
    McUpgradeSetup* setup = (McUpgradeSetup*)gameObj->anim.placementData;

    if (GameBit_Get(setup->collectedGameBit) != 0)
    {
        gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    else if (ObjTrigger_IsSet(obj) != 0)
    {
        GameBit_Set(setup->collectedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
    else
    {
        objRenderFn_80041018(obj);
    }
}

void mcupgrade_init(int obj) { ((GameObject*)obj)->animEventCallback = mcupgrade_SeqFn; }
