#ifndef MAIN_DLL_NW_DLL_01A4_NWICE_H_
#define MAIN_DLL_NW_DLL_01A4_NWICE_H_

#include "types.h"

typedef struct NwIcePlacement
{
    u8 pad0[0x1B - 0x0];
    u8 linkId; /* pairing key: matched against another nwice's 0x1B to find linkedObj */
    u8 pad1C[0x20 - 0x1C];
} NwIcePlacement;

typedef struct NwIceState
{
    int* linkedObj;
} NwIceState;

int NW_ice_getExtraSize(void);
void NW_ice_free(int obj);
void NW_ice_render(void);
void NW_ice_update(int* obj);
void NW_ice_init(int obj);

#endif /* MAIN_DLL_NW_DLL_01A4_NWICE_H_ */
