/*
 * mcupgradema (DLL 0x2B8) - the "ma" variant of the mcupgrade one-shot
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
#include "main/dll/dll_80220608_shared.h"
/* mcupgrade_state.h: only McUpgradeMaSetup + MCUPGRADE_OBJ_FLAG_COLLECTED used here. */
#include "main/dll/mcupgrade_state.h"
#include "main/game_object.h"
#include "main/dll/mcstaffeffe_state.h"

int mcstaffeffe_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    McStaffEffectObject* staffEffect = (McStaffEffectObject*)obj;
    int staff;
    int i;

    if ((void*)Obj_GetPlayerObject() == NULL)
    {
        return 0;
    }
    staff = fn_802966CC();
    if ((void*)staff == NULL)
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
            staffSetGlow(staff, 5, (u8)staffEffect->staffGlowLevel);
            break;
        case MCSTAFFEFFECT_EVENT_CLEAR_GLOW:
            staffSetGlow(staff, 5, 0);
            break;
        }
    }
    return 0;
}

/* obj is a word, not a pointer: the shared-header prototype fixes the
   original signature as int, and the integral param pools low in the saved
   regs to match retail coloring (CLAUDE.md recipe #126). */
void mcupgradema_update(int obj)
{
    GameObject* gameObj = (GameObject*)obj;
    McUpgradeMaSetup* setup = (McUpgradeMaSetup*)gameObj->anim.placementData;

    if ((u32)GameBit_Get(setup->collectedGameBit) != 0)
    {
        *(u8*)&gameObj->anim.resetHitboxMode |= MCUPGRADE_OBJ_FLAG_COLLECTED;
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

void mcupgradema_init(int obj)
{
    ((GameObject*)obj)->animEventCallback = mcupgradema_SeqFn;
}
