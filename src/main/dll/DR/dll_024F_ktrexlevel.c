/*
 * ktrexlevel (DLL 0x24F) - level controller object for the SharpClaw
 * T-rex (Galdon) arena in the DarkIce Mines / Krazoa region.
 *
 * On init it forces the level's sky/cloud/lighting setup, primes the
 * path-selection game bits and arms its active-level bit; on the first
 * update tick it kicks off the environment fx and weather, then each
 * tick mirrors a status game bit into a shared global. The path game
 * bits (0x54a/0x54e/0x552/0x556, selected via 0x55a/0x55b) gate which
 * branch of the arena is open. The remaining bit literals are cross-TU
 * game bits without established names.
 *
 * The 4-byte extra block holds a single f32 scratch value seeded at init.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

int ktrexlevel_getExtraSize(void) { return 0x4; }

int ktrexlevel_getObjectTypeId(void) { return 0x0; }

void ktrexlevel_hitDetect(void)
{
}

void ktrexlevel_initialise(void)
{
}

void ktrexlevel_release(void)
{
}

void ktrexlevel_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E67A0);
    }
}

void ktrexlevel_clearPathGameBits(void)
{
    GameBit_Set(0x54a, 0);
    GameBit_Set(0x54e, 0);
    GameBit_Set(0x552, 0);
    GameBit_Set(0x556, 0);
}

void ktrexlevel_free(void)
{
    GameBit_Set(0xefd, 0);
    GameBit_Set(0xcd1, 0);
    GameBit_Set(0xccd, 0);
    GameBit_Set(0xccf, 0);
    GameBit_Set(0xcd0, 0);
    GameBit_Set(0xedb, 0);
    GameBit_Set(0xcbb, 0);
}

void ktrexlevel_updatePathGameBits(void)
{
    if (GameBit_Get(0x55a) != 0)
    {
        GameBit_Set(0x54a, 2);
        GameBit_Set(0x54e, 2);
        GameBit_Set(0x552, 1);
        GameBit_Set(0x556, 1);
    }
    else if (GameBit_Get(0x55b) != 0)
    {
        GameBit_Set(0x54a, 1);
        GameBit_Set(0x54e, 1);
        GameBit_Set(0x552, 2);
        GameBit_Set(0x556, 2);
    }
}

void ktrexlevel_init(int obj)
{
    char* extra = ((GameObject*)obj)->extra;
    setDrawCloudsAndLights(0);
    GameBit_Set(0x572, 0);
    GameBit_Set(0x56e, 1);
    GameBit_Set(0x566, 1);
    GameBit_Set(0x569, 1);
    *(f32*)extra = lbl_803E67A8;
    GameBit_Set(0x55a, 1);
    GameBit_Set(0x54a, 2);
    GameBit_Set(0x54e, 2);
    GameBit_Set(0x552, 1);
    GameBit_Set(0x556, 1);
    ((GameObject*)obj)->unkF4 = 0;
    GameBit_Set(0xefd, 1);
}

void ktrexlevel_update(int obj)
{
    if (((GameObject*)obj)->unkF4 == 0)
    {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, obj, 0x18f, 0);
        getEnvfxAct(obj, obj, 0x18e, 0);
        getEnvfxAct(obj, obj, 0x190, 0);
        skyFn_80088e54(1, lbl_803E67A4);
        GameBit_Set(0x55e, 1);
        ((GameObject*)obj)->unkF4 = 1;
    }
    lbl_803DDD40 = GameBit_Get(0x572);
}
