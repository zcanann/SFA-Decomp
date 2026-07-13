#ifndef MAIN_OBJPRINT_CHARACTER_API_H_
#define MAIN_OBJPRINT_CHARACTER_API_H_

#include "global.h"
#include "main/game_object.h"

typedef struct CharacterEyeAnimState
{
    u8 pad00[0x14];
    s16 headYaw;
    u8 pad16[0x1e - 0x16];
    s8 blinkState;
    s8 blinkTimer;
    s8 movementTimer;
    u8 pad21;
    s16 movementStep;
    s32 movementTarget;
} CharacterEyeAnimState;

STATIC_ASSERT(sizeof(CharacterEyeAnimState) == 0x28);
STATIC_ASSERT(offsetof(CharacterEyeAnimState, headYaw) == 0x14);

void characterDoEyeAnims(GameObject* obj, CharacterEyeAnimState* state);
void fn_8003B0D0(GameObject* obj, GameObject* target, CharacterEyeAnimState* state, int maxAngle);

#define characterDoEyeAnimsState(obj, state) characterDoEyeAnims((obj), (CharacterEyeAnimState*)(state))
#define characterDoEyeAnimsIntStateLegacy(obj, state)                                                          \
    ((void (*)(GameObject*, int))characterDoEyeAnims)((obj), (state))

#endif /* MAIN_OBJPRINT_CHARACTER_API_H_ */
