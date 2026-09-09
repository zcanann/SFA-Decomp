#ifndef MAIN_GAMETEXT_LOOKUP_H_
#define MAIN_GAMETEXT_LOOKUP_H_

#include "global.h"

typedef struct GameTextDef {
    u16 identifier;
    u16 count;
    u8 boxId;
    u8 alignH;
    u8 alignV;
    u8 language;
    char** strings;
} GameTextDef;

STATIC_ASSERT(sizeof(GameTextDef) == 0xc);
STATIC_ASSERT(offsetof(GameTextDef, strings) == 0x8);
STATIC_ASSERT(offsetof(GameTextDef, count) == 0x2);
STATIC_ASSERT(offsetof(GameTextDef, boxId) == 0x4);

GameTextDef* gameTextGet(int textId);

#endif /* MAIN_GAMETEXT_LOOKUP_H_ */
