#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
void mcstaffeffe_render(int obj)
{
    fn_80098B18(obj, *(f32 *)(obj + 0x8), (u8)*(int *)(obj + 0xf4), 0, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcstaffeffe_update(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void mcstaffeffe_init(int obj, int setup)
{
    *(int *)(obj + 0xbc) = (int)fn_802391C4;
    switch (*(u8 *)(setup + 0x1b)) {
    case 0:
        *(int *)(obj + 0xf4) = 4;
        *(int *)(obj + 0xf8) = 1;
        break;
    case 1:
        *(int *)(obj + 0xf4) = 5;
        *(int *)(obj + 0xf8) = 5;
        break;
    case 2:
        *(int *)(obj + 0xf4) = 6;
        *(int *)(obj + 0xf8) = 2;
        break;
    case 3:
        *(int *)(obj + 0xf4) = 0xb;
        *(int *)(obj + 0xf8) = 3;
        break;
    default:
        *(int *)(obj + 0xf4) = 4;
        *(int *)(obj + 0xf8) = 1;
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
