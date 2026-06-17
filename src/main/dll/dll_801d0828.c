#include "main/game_object.h"



int EdibleMushroom_SeqFn(int* obj)
{
    *(u8*)(*(int*)&((GameObject*)obj)->extra + 0x139) = 1;
    return 0;
}
