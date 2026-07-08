#ifndef MAIN_DLL_SB_DLL_01F7_SBSHIPGUNBROKE_H_
#define MAIN_DLL_SB_DLL_01F7_SBSHIPGUNBROKE_H_

#include "main/game_object.h"

/* Placement record for the broken ship-gun: only the destroyed-flag
   GameBit index (0x1E) is read by this DLL. */
typedef struct SBShipGunBrokePlacement
{
    u8 pad0[0x1E];
    s16 destroyedGameBit; /* 0x1E */
} SBShipGunBrokePlacement;

int SB_ShipGunBroke_getExtraSize(void);
int SB_ShipGunBroke_getObjectTypeId(void);
void SB_ShipGunBroke_free(void);
void SB_ShipGunBroke_render(GameObject* obj, int p2, int p3, int p4, int p5);
void SB_ShipGunBroke_hitDetect(void);
void SB_ShipGunBroke_update(GameObject* obj);
void SB_ShipGunBroke_init(void);
void SB_ShipGunBroke_release(void);
void SB_ShipGunBroke_initialise(void);

#endif /* MAIN_DLL_SB_DLL_01F7_SBSHIPGUNBROKE_H_ */
