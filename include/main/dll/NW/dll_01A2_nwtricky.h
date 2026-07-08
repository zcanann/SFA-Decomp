#ifndef MAIN_DLL_NW_DLL_01A2_NWTRICKY_H_
#define MAIN_DLL_NW_DLL_01A2_NWTRICKY_H_

#include "types.h"

typedef struct NwTrickyState
{
    u8 pad0[0x4 - 0x0];
    f32 timer;
} NwTrickyState;

typedef struct NwTrickyIds
{
    int ids[3];
} NwTrickyIds;

typedef struct NwObjPos
{
    u8 pad[0x18];
    f32 worldPos[3];
} NwObjPos;

int NW_tricky_getExtraSize(void);
int NW_tricky_SeqFn(void);
void NW_tricky_free(int obj);
void NW_tricky_update(int* obj);
void NW_tricky_init(int* obj);

#endif /* MAIN_DLL_NW_DLL_01A2_NWTRICKY_H_ */
