/*
 * MCUpgradeMa (DLL 0x2B8) - the "ma" variant of the mcupgrade one-shot
 * upgrade pickup, sharing mcupgrade's state/setup layout.
 *
 * mcupgradema_update gates the object on its placement's collectedGameBit:
 * once the bit is set the object is flagged collected; until then, an
 * object-trigger hit sets the bit and runs trigger sequence 0 (the pickup
 * sequence). mcupgradema_init wires the anim event callback to
 * mcupgradema_SeqFn (which lives in the mcupgrade TU, DLL 0x2B7).
 *
 * This TU also owns mcstaffeffe_SeqFn, the sequence handler for the staff
 * glow effect object (DLL 0x2B9 mcstaffeffe wires its callback to it): per
 * sequence event it forces the staff glow to a fixed level, restores it to
 * the object's configured level, or clears it.
 */
#include "dlls/objects/226.h"
#include "main/dll/dll_02B8_mcupgradema.h"
#include "main/dll/player_objects.h"
#include "main/gamebits.h"
#include "main/obj_trigger.h"
#include "main/objprint_render_api.h"
#include "sys/objects.h"
#include "main/objseq.h"

void mcupgradema_update(GameObject* obj)
{
    GameObject* gameObj = obj;
    McUpgradeMaSetup* setup = (McUpgradeMaSetup*)gameObj->anim.placementData;

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

void mcupgradema_init(GameObject* obj)
{
    obj->animEventCallback = mcupgradema_SeqFn;
}

int mcstaffeffe_SeqFn(GameObject* staffEffect, int unused, ObjSeqState* animUpdate)
{
    GameObject* player;
    GameObject* staff;
    int i;

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return 0;
    }
    staff = objGetFirstChild(player);
    if (staff == NULL)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case MCSTAFFEFFECT_EVENT_FORCE_GLOW:
            staffSetGlow(staff, 5, 1);
            break;
        case MCSTAFFEFFECT_EVENT_RESTORE_GLOW:
            staffSetGlow(staff, 5, (u8)staffEffect->userData2);
            break;
        case MCSTAFFEFFECT_EVENT_CLEAR_GLOW:
            staffSetGlow(staff, 5, 0);
            break;
        }
    }
    return 0;
}

ObjectDescriptor gMCUpgradeMaObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)mcupgradema_init,
    (ObjectDescriptorCallback)mcupgradema_update,
    0,
    0,
    0,
    0,
    0,
};
