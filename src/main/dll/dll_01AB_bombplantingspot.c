/* DLL 0x01AB — bombplantingspot (Sauria bomb planting spot / trigger). TU: 0x801D3FF4–0x801D4198. */
#include "main/objseq.h"

extern u32 GameBit_Get(int eventId);

#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/SH/SHrocketmushroom.h"

extern u32 GameBit_Get(int eventId);
extern int gameBitDecrement(int bit);
extern int ObjTrigger_IsSetById(void* obj, int triggerId);
extern void objRenderFn_80041018(void* obj);

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER 0x196
#define BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG 0x08
#define BOMBPLANTINGSPOT_READY_FLAG 0x10

void bombplantingspot_update(void* obj)
{
    extern void GameBit_Set(int eventId, int value); /* #57 */
    BombPlantingSpotMapData* mapData = *(BombPlantingSpotMapData**)&((GameObject*)obj)->anim.placementData;
    s32 trigBit;

    ((GameObject*)obj)->anim.rotX = (s16)(mapData->yawByte << 8);

    trigBit = mapData->requiredGameBit;
    if (trigBit != -1 && GameBit_Get(trigBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        return;
    }

    if (GameBit_Get(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_READY_FLAG;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_READY_FLAG;
    }

    if (ObjTrigger_IsSetById(obj, BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) != 0)
    {
        gameBitDecrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
        GameBit_Set(mapData->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x4) != 0 &&
        GameBit_Get(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        GameBit_Set(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER, 1);
    }

    if (GameBit_Get(mapData->plantedGameBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        objRenderFn_80041018(obj);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
    }
}

void bombplantingspot_init(void* obj, BombPlantingSpotMapData* mapData)
{
    ((GameObject*)obj)->objectFlags |= 0x4000;
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->yawByte << 8);
}

