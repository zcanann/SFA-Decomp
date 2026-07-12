#ifndef MAIN_DLL_DFPOBJCREATORSTATE_STRUCT_H_
#define MAIN_DLL_DFPOBJCREATORSTATE_STRUCT_H_

#include "types.h"
#include "main/game_object.h"

typedef struct DfpObjCreatorState
{
    GameObject* spawnedObj;
    u8 unk04[8];
    s16 gameBit; /* 0x0C: spawn gate */
    s16 spawnPeriod; /* 0x0E */
    s16 spawnTimer; /* 0x10 */
    s16 unk12;
    s16 unk14;
    s16 unk16;
    u8 unk18[4];
} DfpObjCreatorState;

#endif
