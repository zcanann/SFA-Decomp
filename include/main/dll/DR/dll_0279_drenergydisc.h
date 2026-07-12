#ifndef MAIN_DLL_DR_DLL_0279_DRENERGYDISC_H_
#define MAIN_DLL_DR_DLL_0279_DRENERGYDISC_H_

#include "global.h"
#include "main/game_object.h"

typedef struct DrEnergyDiscState
{
    u8 activated : 1;
} DrEnergyDiscState;

extern int lbl_803DC380;
extern f32 lbl_803E6BB0;

typedef struct DrenergydiscPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 moveGameBit;   /* 0x1E */
    s16 activeGameBit; /* 0x20 */
    u8 pad22[0x28 - 0x22];
} DrenergydiscPlacement;

int DR_EnergyDisc_getExtraSize(void);
int DR_EnergyDisc_getObjectTypeId(void);
void DR_EnergyDisc_free(void);
void DR_EnergyDisc_render(void);
void DR_EnergyDisc_hitDetect(void);
void DR_EnergyDisc_update(GameObject* obj);
void DR_EnergyDisc_init(u8* obj, u8* setup);
void DR_EnergyDisc_release(void);
void DR_EnergyDisc_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0279_DRENERGYDISC_H_ */
