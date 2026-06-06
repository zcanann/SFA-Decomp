#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#pragma peephole on
#pragma scheduling off
void mcstaffeffe_render(int obj)
{
    fn_80098B18(obj, ((GameObject *)obj)->anim.rootMotionScale, (u8)((GameObject *)obj)->unkF4, 0, 0, 0);
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
    *(int *)(obj + 0xbc) = (int)mcstaffeffe_SeqFn;
    switch (*(u8 *)(setup + 0x1b)) {
    case 0:
        ((GameObject *)obj)->unkF4 = 4;
        ((GameObject *)obj)->unkF8 = 1;
        break;
    case 1:
        ((GameObject *)obj)->unkF4 = 5;
        ((GameObject *)obj)->unkF8 = 5;
        break;
    case 2:
        ((GameObject *)obj)->unkF4 = 6;
        ((GameObject *)obj)->unkF8 = 2;
        break;
    case 3:
        ((GameObject *)obj)->unkF4 = 0xb;
        ((GameObject *)obj)->unkF8 = 3;
        break;
    default:
        ((GameObject *)obj)->unkF4 = 4;
        ((GameObject *)obj)->unkF8 = 1;
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
