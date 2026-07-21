/* DLL 0x01AB - bombplantingspot (Sauria bomb planting spot / trigger). TU: 0x801D3FF4-0x801D4198. */
#include "main/objseq.h"
#include "main/objprint_render_api.h"
#include "main/game_object.h"
#include "main/obj_trigger.h"
#include "main/dll/dll_01AB_bombplantingspot.h"
#include "main/gamebits.h"
#include "main/gameloop_api.h"

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER 0x196

void BombPlantingSpot_update(GameObject* obj)
{
    BombPlantingSpotPlacement* placement = (BombPlantingSpotPlacement*)obj->anim.placementData;
    s32 requiredGameBit;

    obj->anim.rotX = (s16)(placement->rotX << 8);

    requiredGameBit = placement->requiredGameBit;
    if (requiredGameBit != -1 && mainGetBit(requiredGameBit) == 0)
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return;
    }

    if (mainGetBit(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) == 0)
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    if (ObjTrigger_IsSetById((int)obj, BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) != 0)
    {
        gameBitDecrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
        mainSetBits(placement->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    }
    else if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0 &&
        mainGetBit(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        mainSetBits(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER, 1);
    }

    if (mainGetBit(placement->plantedGameBit) == 0)
    {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        objRenderFn_80041018(obj);
    }
    else
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
}

void BombPlantingSpot_init(GameObject* obj, BombPlantingSpotPlacement* placement)
{
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    obj->anim.rotX = (s16)(placement->rotX << 8);
}
