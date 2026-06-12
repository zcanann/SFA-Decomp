#include "main/audio/vid_get.h"

extern u32* vidRoot;

u32* get_vidlist(u32 key)
{
    u32* node;
    u32 value;

    node = vidRoot;
    while (node != NULL)
    {
        value = node[2];
        if (value == key)
        {
            return node;
        }
        if (value > key)
        {
            break;
        }
        node = (u32*)node[0];
    }
    return NULL;
}
