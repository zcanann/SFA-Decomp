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
#include "main/dll/dll_02B8_mcupgradema.h"
#include "main/objprint_dolphin.h"
#include "main/dll/dll_02B9_mcstaffeffe.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/player_objects.h"
/* mcupgrade_state.h: only McUpgradeMaSetup + MCUPGRADE_OBJ_FLAG_COLLECTED used here. */
#include "main/dll/mcupgrade_state.h"
#include "main/game_object.h"
#include "main/dll/mcstaffeffe_state.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/object_api.h"
#include "main/objlib.h"
#include "main/objseq.h"

/* obj is a word, not a pointer: the shared-header prototype fixes the
   original signature as int, and the integral param pools low in the saved
   regs to match retail coloring (CLAUDE.md recipe #126). */
void mcupgradema_update(GameObject* obj)
{
    GameObject* gameObj = obj;
    McUpgradeMaSetup* setup = (McUpgradeMaSetup*)gameObj->anim.placementData;

    if ((u32)mainGetBit(setup->collectedGameBit) != 0)
    {
        *(u8*)&gameObj->anim.resetHitboxMode |= MCUPGRADE_OBJ_FLAG_COLLECTED;
    }
    else if (ObjTrigger_IsSet((int)obj) != 0)
    {
        mainSetBits(setup->collectedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
    else
    {
        objRenderFn_80041018((GameObject*)obj);
    }
}

void mcupgradema_init(GameObject* obj)
{
    obj->animEventCallback = mcupgradema_SeqFn;
}

int mcstaffeffe_SeqFn(McStaffEffectObject* staffEffect, int unused, ObjAnimUpdateState* animUpdate)
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
            staffSetGlow(staff, 5, (u8)staffEffect->staffGlowLevel);
            break;
        case MCSTAFFEFFECT_EVENT_CLEAR_GLOW:
            staffSetGlow(staff, 5, 0);
            break;
        }
    }
    return 0;
}
