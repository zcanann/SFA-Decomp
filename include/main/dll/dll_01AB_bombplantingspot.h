#ifndef MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_
#define MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct BombPlantingSpotMapData
{
    ObjPlacement base;
    s8 yawByte;
    u8 pad19[0x1E - 0x19];
    s16 plantedGameBit;
    s16 requiredGameBit;
} BombPlantingSpotMapData;

STATIC_ASSERT(offsetof(BombPlantingSpotMapData, yawByte) == 0x18);
STATIC_ASSERT(offsetof(BombPlantingSpotMapData, plantedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BombPlantingSpotMapData, requiredGameBit) == 0x20);

void BombPlantingSpot_init(GameObject* obj, BombPlantingSpotMapData* mapData);
void BombPlantingSpot_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_ */
