#include "main/dll/dll_80220608_shared.h"
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

void mcupgradema_init(int obj) { ((GameObject*)obj)->animEventCallback = (void*)mcupgradema_SeqFn; }
