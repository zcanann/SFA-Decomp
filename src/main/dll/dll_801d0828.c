#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/dll/projball1D8.h"
#include "main/objseq.h"

extern uint GameBit_Get();

extern uint GameBit_Get(int id);

int EdibleMushroom_SeqFn(int* obj)
{
    *(u8*)(*(int*)&((GameObject*)obj)->extra + 0x139) = 1;
    return 0;
}
