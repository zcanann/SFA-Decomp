#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/cntcounter_state.h"

int cntcounter_getExtraSize(void) { return 8; }

int cntcounter_getObjectTypeId(void) { return 0; }

void cntcounter_free(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    if (((CntCounterState *)state)->unk4 != 0) {
        set_hudNumber_803db278(-1);
    }
}

void cntcounter_hitDetect(void) {}

void cntcounter_render(void) {}

void cntcounter_init(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    ((CntCounterState *)state)->unk4 = 0;
    ((CntCounterState *)state)->unk0 = 0;
}

#pragma peephole off
#pragma scheduling off
void cntcounter_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;

    if (((CntCounterState *)state)->unk0 != 0) {
        int bit;
        if (((CntCounterState *)state)->unk4 != 0) {
            set_hudNumber_803db278(((CntCounterState *)state)->unk0);
        }
        bit = GameBit_Get(*(s16 *)(setup + 0x20));
        if (bit != 0) {
            GameBit_Set(*(s16 *)(setup + 0x20), 0);
            ((CntCounterState *)state)->unk0 -= bit;
            if (((CntCounterState *)state)->unk0 <= 0) {
                ((CntCounterState *)state)->unk0 = 0;
                GameBit_Set(*(s16 *)(setup + 0x1e), 1);
                if (((CntCounterState *)state)->unk4 != 0) {
                    set_hudNumber_803db278(-1);
                }
                ((CntCounterState *)state)->unk4 = 0;
            }
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            ((CntCounterState *)state)->unk4 = *(u8 *)(setup + 0x19);
            ((CntCounterState *)state)->unk0 = *(s16 *)(setup + 0x1a);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void cntcounter_release(void) {}

void cntcounter_initialise(void) {}
