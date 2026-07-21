#ifndef MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_
#define MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct BombPlantingSpotPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19[0x1E - 0x19];
    s16 plantedGameBit;
    s16 requiredGameBit;
} BombPlantingSpotPlacement;

STATIC_ASSERT(offsetof(BombPlantingSpotPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(BombPlantingSpotPlacement, plantedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BombPlantingSpotPlacement, requiredGameBit) == 0x20);
STATIC_ASSERT(sizeof(BombPlantingSpotPlacement) == 0x24);

void BombPlantingSpot_init(GameObject* obj, BombPlantingSpotPlacement* placement);
void BombPlantingSpot_update(GameObject* obj);

extern ObjectDescriptor gBombPlantingSpotObjDescriptor;

#endif /* MAIN_DLL_DLL_01AB_BOMBPLANTINGSPOT_H_ */
