#ifndef MAIN_GAMETEXT_BOX_API_H_
#define MAIN_GAMETEXT_BOX_API_H_

#include "global.h"

typedef struct GameTextBox
{
    u16 unk00;
    u16 maxWidth;
    u16 unk04;
    u16 maxHeight;
    u16 width;
    u16 height;
    f32 scale;
    u8 alignH;
    u8 alignV;
    u8 alignment;
    u8 style;
    s16 x;
    s16 y;
    s16 cursorX;
    s16 cursorY;
    u16 flags;
    u8 alpha;
    u8 unk1F;
} GameTextBox;

typedef GameTextBox TextSlot;

#define GAMETEXT_BOX_COUNT 148

STATIC_ASSERT(sizeof(GameTextBox) == 0x20);
STATIC_ASSERT(offsetof(GameTextBox, unk00) == 0x00);
STATIC_ASSERT(offsetof(GameTextBox, maxWidth) == 0x02);
STATIC_ASSERT(offsetof(GameTextBox, width) == 0x08);
STATIC_ASSERT(offsetof(GameTextBox, height) == 0x0A);
STATIC_ASSERT(offsetof(GameTextBox, alignH) == 0x10);
STATIC_ASSERT(offsetof(GameTextBox, y) == 0x16);
STATIC_ASSERT(offsetof(GameTextBox, style) == 0x13);
STATIC_ASSERT(offsetof(GameTextBox, alpha) == 0x1E);

GameTextBox* gameTextGetBox(int box);
GameTextBox* gameTextGetCurBox(void);

#endif /* MAIN_GAMETEXT_BOX_API_H_ */
