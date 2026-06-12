#ifndef MAIN_DLL_TITLEMENUITEM_STRUCT_H_
#define MAIN_DLL_TITLEMENUITEM_STRUCT_H_

#include "types.h"

typedef struct TitleMenuItem
{
    s16 x;
    s16 y;
    u8 flags;
    u8 kind;
    s8 frameDelay;
    u8 pad7;
    s16 minValue;
    s16 maxValue;
    s16 value;

    union
    {
        s16 textId;

        struct
        {
            u16 phraseId;
            u16 windowId;
        } window;
    } extra;
} TitleMenuItem;

#endif
