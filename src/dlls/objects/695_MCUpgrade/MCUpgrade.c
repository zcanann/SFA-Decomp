/*
 * MCUpgrade (DLL 0x2B7) - a one-shot upgrade pickup object.
 *
 * mcupgrade_update gates the object on its placement's collectedGameBit:
 * once that bit is set the object is flagged collected; until then, an
 * object-trigger hit sets the bit and runs trigger sequence 0 (the
 * pickup sequence).
 *
 * mcupgrade_init wires the object's anim event callback to mcupgrade_SeqFn,
 * which is provided by the preceding CNThitObjec TU. This DOL-confirmed TU
 * also provides mcupgradema_SeqFn to the following MCUpgradeMa DLL; that
 * callback shows the HUD, displays NPC dialogue 0x468, then hides the HUD.
 */
#include "dlls/objects/694_CNThitObjec.h"
#include "main/dll/mcupgrade_state.h"
#include "main/dll/player_api.h"
#include "main/gamebits.h"
#include "main/game_ui_interface.h"
#include "sys/objects.h"
#include "main/objseq.h"
#include "main/dll/tricky_api.h"
#include "main/obj_trigger.h"
#include "main/objprint_render_api.h"
#include "main/dll/dll_02B7_mcupgrade.h"
#include "main/dll/dll_02B8_mcupgradema.h"

void mcupgrade_update(GameObject* obj)
{
    GameObject* gameObj = obj;
    McUpgradeSetup* setup = (McUpgradeSetup*)gameObj->anim.placementData;

    if (mainGetBit(setup->collectedGameBit) != 0)
    {
        gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    else if (ObjTrigger_IsSet(obj) != 0)
    {
        mainSetBits(setup->collectedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
    else
    {
        objUpdateHitVolumeTransforms(obj);
    }
}

void mcupgrade_init(GameObject* obj)
{
    obj->animEventCallback = mcupgrade_SeqFn;
}

int mcupgradema_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case MCUPGRADEMA_EVENT_SHOW_HUD:
            setHudForceShowMask(1);
            break;
        case MCUPGRADEMA_EVENT_SHOW_DIALOGUE:
            playerAddMaxMagic(Obj_GetPlayerObject(), 0x19);
            (*gGameUIInterface)->showNpcDialogue(0x468, 0x14, 0x8c, 0);
            break;
        case MCUPGRADEMA_EVENT_HIDE_HUD:
            setHudForceShowMask(0);
            break;
        }
    }
    return 0;
}

ObjectDescriptor gMCUpgradeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)mcupgrade_init,
    (ObjectDescriptorCallback)mcupgrade_update,
    0,
    0,
    0,
    0,
    0,
};
