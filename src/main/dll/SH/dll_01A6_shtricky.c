#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"
#include "main/objseq.h"

extern uint GameBit_Get();
extern undefined4 GameBit_Set();

extern int* getTrickyObject(void);
extern uint GameBit_Get(int id);

int sh_tricky_getExtraSize(void)
{
    return 1;
}

void sh_tricky_update(int* obj)
{
    u8* state;
    int* tricky;

    state = ((GameObject*)obj)->extra;
    tricky = getTrickyObject();
    if (tricky == NULL)
    {
        return;
    }

    switch (state[0])
    {
    case 0:
        if (GameBit_Get(0x94) != 0)
        {
            GameBit_Set(0x4e4, 0);
            GameBit_Set(0x4e5, 0);
            GameBit_Set(0xc11, 1);
            state[0] = 1;
        }
        break;
    case 1:
        state[0] = 2;
        break;
    case 2:
        if (((int (*)(int*, int*))(*(int*)(*(int*)(tricky[0x1a]) + 0x38)))(tricky, obj) !=
            0)
        {
            state[0] = 3;
        }
        break;
    case 3:
        if (GameBit_Get(0xbf) != 0)
        {
            GameBit_Set(0x4e4, 1);
            GameBit_Set(0x4e5, 1);
            GameBit_Set(0xc11, 0);
        }
        break;
    case 4:
        break;
    }
}

int EdibleMushroom_SeqFn(int* obj);

void sh_tricky_init(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0xbf) != 0)
    {
        *state = 4;
    }
    else
    {
        *state = 0;
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}
