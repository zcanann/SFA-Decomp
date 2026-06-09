#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/mcstaffeffe_state.h"

void mcstaffeffe_render(int obj)
{
    McStaffEffectObject *staffEffect = (McStaffEffectObject *)obj;

    fn_80098B18(obj, staffEffect->anim.rootMotionScale, (u8)staffEffect->particleType, 0, 0, 0);
}

void mcstaffeffe_update(void) {}

void mcstaffeffe_init(int obj, int setup)
{
    McStaffEffectObject *staffEffect = (McStaffEffectObject *)obj;
    McStaffEffectSetup *placement = (McStaffEffectSetup *)setup;

    ((GameObject *)staffEffect)->animEventCallback = (void *)mcstaffeffe_SeqFn;
    switch (placement->effectProfile) {
    case 0:
        staffEffect->particleType = 4;
        staffEffect->staffGlowLevel = 1;
        break;
    case 1:
        staffEffect->particleType = 5;
        staffEffect->staffGlowLevel = 5;
        break;
    case 2:
        staffEffect->particleType = 6;
        staffEffect->staffGlowLevel = 2;
        break;
    case 3:
        staffEffect->particleType = 0xb;
        staffEffect->staffGlowLevel = 3;
        break;
    default:
        staffEffect->particleType = 4;
        staffEffect->staffGlowLevel = 1;
        break;
    }
}
