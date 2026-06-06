#include "main/dll/dll_80220608_shared.h"
#include "main/dll/cntcounter_state.h"

#pragma peephole on
#pragma scheduling on
int cntcounter_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int cntcounter_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cntcounter_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (((CntCounterState *)state)->unk4 != 0) {
        set_hudNumber_803db278(-1);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cntcounter_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cntcounter_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cntcounter_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((CntCounterState *)state)->unk4 = 0;
    ((CntCounterState *)state)->unk0 = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cntcounter_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

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

#pragma peephole on
#pragma scheduling on
void cntcounter_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cntcounter_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
