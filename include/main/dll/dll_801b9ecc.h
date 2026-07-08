#ifndef MAIN_DLL_DLL_801B9ECC_H_
#define MAIN_DLL_DLL_801B9ECC_H_

#include "types.h"
#include "main/dll/baddie_state.h"

typedef void (*Dim2QueryTargetMoveFn)(int obj, void* targetObj, int queryFlags, u16* animId, s16* outParam,
                                      u16* targetDistance);
typedef u8 (*Dim2CheckTargetRangeFn)(int obj, BaddieState* state, f32 rangeScale);
typedef void (*Dim2RequestControlModeFn)(int obj, BaddieState* state, int controlMode);

typedef struct Dim2BaddieControlInterface
{
    u8 pad00[0x14];
    Dim2QueryTargetMoveFn queryTargetMove;
    Dim2CheckTargetRangeFn checkTargetRange;
} Dim2BaddieControlInterface;

typedef struct Dim2PlayerInterface
{
    u8 pad00[0x14];
    Dim2RequestControlModeFn requestControlMode;
} Dim2PlayerInterface;

typedef struct DimAnimTable
{
    u8 pad[0x168];    /* 0x000 */
    s16 surprised[6]; /* 0x168: far random "surprised" anim ids */
    s16 group3[8];    /* 0x174: hitPoints==3 round-robin anim ids */
    s16 group2[8];    /* 0x184: hitPoints==2 round-robin anim ids */
    s16 group1[8];    /* 0x194: hitPoints==1 round-robin anim ids */
} DimAnimTable;

int fn_801B9ECC(int a, int obj);

#endif /* MAIN_DLL_DLL_801B9ECC_H_ */
