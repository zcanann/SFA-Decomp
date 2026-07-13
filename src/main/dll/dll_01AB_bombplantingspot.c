/* DLL 0x01AB — bombplantingspot (Sauria bomb planting spot / trigger). TU: 0x801D3FF4–0x801D4198. */
#include "main/objseq.h"
#include "main/objprint_dolphin.h"
#include "main/game_object.h"
#include "main/obj_trigger.h"
#include "main/dll/dll_01AB_bombplantingspot.h"
#include "main/gamebits.h"
#include "main/gameloop_api.h"

#define BOMBPLANTINGSPOT_OBJFLAG_HIDDEN 0x4000


#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER 0x196
#define BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG 0x08
#define BOMBPLANTINGSPOT_READY_FLAG 0x10

void BombPlantingSpot_update(GameObject* obj)
{
    BombPlantingSpotMapData* mapData = (BombPlantingSpotMapData*)obj->anim.placementData;
    s32 trigBit;

    obj->anim.rotX = (s16)(mapData->yawByte << 8);

    trigBit = mapData->requiredGameBit;
    if (trigBit != -1 && mainGetBit(trigBit) == 0)
    {
        *(u8*)&obj->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        return;
    }

    if (mainGetBit(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) == 0)
    {
        *(u8*)&obj->anim.resetHitboxMode |= BOMBPLANTINGSPOT_READY_FLAG;
    }
    else
    {
        *(u8*)&obj->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_READY_FLAG;
    }

    if (ObjTrigger_IsSetById((int)obj, BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) != 0)
    {
        gameBitDecrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
        mainSetBits(mapData->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    }
    else if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0 &&
        mainGetBit(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        mainSetBits(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER, 1);
    }

    if (mainGetBit(mapData->plantedGameBit) == 0)
    {
        *(u8*)&obj->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        objRenderFn_80041018((GameObject*)obj);
    }
    else
    {
        *(u8*)&obj->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
    }
}

void BombPlantingSpot_init(GameObject *obj, BombPlantingSpotMapData* mapData)
{
    (obj)->objectFlags |= BOMBPLANTINGSPOT_OBJFLAG_HIDDEN;
    (obj)->anim.rotX = (s16)(mapData->yawByte << 8);
}
