#include "main/dll/dll_80220608_shared.h"

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
    if (*(u8 *)(state + 4) != 0) {
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
    *(u8 *)(state + 4) = 0;
    *(int *)(state + 0) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cntcounter_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(int *)(state + 0) != 0) {
        int bit;
        if (*(u8 *)(state + 4) != 0) {
            set_hudNumber_803db278(*(int *)(state + 0));
        }
        bit = GameBit_Get(*(s16 *)(setup + 0x20));
        if (bit != 0) {
            GameBit_Set(*(s16 *)(setup + 0x20), 0);
            *(int *)(state + 0) -= bit;
            if (*(int *)(state + 0) <= 0) {
                *(int *)(state + 0) = 0;
                GameBit_Set(*(s16 *)(setup + 0x1e), 1);
                if (*(u8 *)(state + 4) != 0) {
                    set_hudNumber_803db278(-1);
                }
                *(u8 *)(state + 4) = 0;
            }
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            *(u8 *)(state + 4) = *(u8 *)(setup + 0x19);
            *(int *)(state + 0) = *(s16 *)(setup + 0x1a);
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
