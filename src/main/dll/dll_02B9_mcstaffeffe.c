/*
 * mcstaffeffe (DLL 0x2B9) - staff visual-effect object.
 *
 * From its placement effectProfile, init selects a particle type and a
 * staff glow level (profiles 0-3, default = profile 0); each render tick
 * spawns the staff particle fx (fn_80098B18) scaled by the object's
 * root-motion scale. update is a no-op. The anim-event callback
 * mcstaffeffe_SeqFn (defined alongside mcupgradema in DLL 0x2B8) drives
 * the player's staff glow from sequence events.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_02B9_mcstaffeffe.h"
#include "main/game_object.h"
#include "main/dll/mcstaffeffe_state.h"

void mcstaffeffe_render(McStaffEffectObject* staffEffect)
{
    fn_80098B18((int)staffEffect, staffEffect->anim.rootMotionScale, (u8)staffEffect->particleType, 0, 0, NULL);
}

void mcstaffeffe_update(void)
{
}

void mcstaffeffe_init(McStaffEffectObject* staffEffect, McStaffEffectSetup* placement)
{
    ((GameObject*)staffEffect)->animEventCallback = mcstaffeffe_SeqFn;
    switch (placement->effectProfile)
    {
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
