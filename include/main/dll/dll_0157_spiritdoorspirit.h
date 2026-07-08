#ifndef MAIN_DLL_DLL_0157_SPIRITDOORSPIRIT_H_
#define MAIN_DLL_DLL_0157_SPIRITDOORSPIRIT_H_

#include "global.h"

/* spiritdoorspirit_getExtraSize == 0x1. */
typedef struct SpiritDoorSpiritState
{
    u8 active; /* gamebit not yet set: render + group 0x4e membership */
} SpiritDoorSpiritState;

typedef struct SpiritdoorspiritPlacement
{
    u8 pad0[0x1E];
    s16 gateGameBit;
    u8 pad20[0x28 - 0x20];
} SpiritdoorspiritPlacement;

STATIC_ASSERT(offsetof(SpiritdoorspiritPlacement, gateGameBit) == 0x1E);

int spiritdoorspirit_getExtraSize(void);
int spiritdoorspirit_getObjectTypeId(void);
void spiritdoorspirit_free(int obj);
void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void spiritdoorspirit_hitDetect(void);
void spiritdoorspirit_update(int* obj);
void spiritdoorspirit_init(int* obj);
void spiritdoorspirit_release(void);
void spiritdoorspirit_initialise(void);

#endif /* MAIN_DLL_DLL_0157_SPIRITDOORSPIRIT_H_ */
