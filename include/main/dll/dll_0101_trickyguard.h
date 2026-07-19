#ifndef MAIN_DLL_DLL_0101_TRICKYGUARD_H_
#define MAIN_DLL_DLL_0101_TRICKYGUARD_H_

#include "main/game_object.h"

typedef struct TrickyGuardPlacement
{
    u8 pad00[0x18];
    u8 yawByte; /* 0x18 */
    u8 pad19;
    s16 armingGameBit; /* 0x1A: -1 = always armed */
    u8 pad1C[0x20 - 0x1C];
} TrickyGuardPlacement;

STATIC_ASSERT(sizeof(TrickyGuardPlacement) == 0x20);

void TrickyGuard_update(GameObject* obj);
void TrickyGuard_init(GameObject* obj, TrickyGuardPlacement* placement);

#endif /* MAIN_DLL_DLL_0101_TRICKYGUARD_H_ */
