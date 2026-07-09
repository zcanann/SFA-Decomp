#ifndef MAIN_DLL_DLL_01F5_SHIPBATTLE_H_
#define MAIN_DLL_DLL_01F5_SHIPBATTLE_H_

#include "main/game_object.h"
#include "global.h"

typedef struct ShipBattleObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 segmentIndex; /* chain index of this segment (-1 = head) */
    s16 unk1A;
    u8 pad1C[0x24 - 0x1C];
    u8 dampingDivisor; /* feeds state->unk24 damping factor */
    u8 pad25[0x28 - 0x25];
} ShipBattleObjectDef;

int ShipBattle_getExtraSize(void);
int ShipBattle_getObjectTypeId(void);
void ShipBattle_free(int* obj);
void ShipBattle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void ShipBattle_hitDetect(void);
void ShipBattle_update(int obj);
void ShipBattle_init(GameObject* obj, int def);
void ShipBattle_release(void);
void ShipBattle_initialise(void);

#endif /* MAIN_DLL_DLL_01F5_SHIPBATTLE_H_ */
