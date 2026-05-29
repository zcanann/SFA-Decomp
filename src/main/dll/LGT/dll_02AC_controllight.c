#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int controllight_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int controllight_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void controllight_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void controllight_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void controllight_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void controllight_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(state + 0) = *(s16 *)(setup + 0x1e);
    *(f32 *)(state + 4) = (f32)*(s16 *)(setup + 0x1a);
    *(u8 *)(state + 8) = *(s8 *)(setup + 0x19) % 2;
    *(u8 *)(state + 9) = 0xff;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void controllight_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 bit = (u8)GameBit_Get(*(s16 *)(state + 0));

    if (bit != *(u8 *)(state + 9)) {
        switch (*(u8 *)(state + 8)) {
        case 0: {
            f32 radius = *(f32 *)(state + 4);
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, bit);
                }
                p++;
            }
            break;
        }
        case 1: {
            f32 radius = *(f32 *)(state + 4);
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, !bit);
                }
                p++;
            }
            break;
        }
        }
    }

    *(u8 *)(state + 9) = bit;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void controllight_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void controllight_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
