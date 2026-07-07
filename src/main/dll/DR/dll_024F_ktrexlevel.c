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

#define KTREXLEVEL_ENVFX_A 0x18f
#define KTREXLEVEL_ENVFX_B 0x18e
#define KTREXLEVEL_ENVFX_C 0x190

int KT_RexLevel_getExtraSize(void) { return 0x4; }

int KT_RexLevel_getObjectTypeId(void) { return 0x0; }

void KT_RexLevel_free(void)
{
    mainSetBits(0xefd, 0);
    mainSetBits(0xcd1, 0);
    mainSetBits(0xccd, 0);
    mainSetBits(0xccf, 0);
    mainSetBits(0xcd0, 0);
    mainSetBits(0xedb, 0);
    mainSetBits(0xcbb, 0);
}

void KT_RexLevel_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E67A0);
    }
}

void KT_RexLevel_hitDetect(void)
{
}

void ktrexlevel_clearPathGameBits(void)
{
    mainSetBits(0x54a, 0);
    mainSetBits(0x54e, 0);
    mainSetBits(0x552, 0);
    mainSetBits(0x556, 0);
}

void ktrexlevel_updatePathGameBits(void)
{
    if (mainGetBit(0x55a) != 0)
    {
        mainSetBits(0x54a, 2);
        mainSetBits(0x54e, 2);
        mainSetBits(0x552, 1);
        mainSetBits(0x556, 1);
    }
    else if (mainGetBit(0x55b) != 0)
    {
        mainSetBits(0x54a, 1);
        mainSetBits(0x54e, 1);
        mainSetBits(0x552, 2);
        mainSetBits(0x556, 2);
    }
}

void KT_RexLevel_update(int obj)
{
    if (((GameObject*)obj)->unkF4 == 0)
    {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, obj, KTREXLEVEL_ENVFX_A, 0);
        getEnvfxAct(obj, obj, KTREXLEVEL_ENVFX_B, 0);
        getEnvfxAct(obj, obj, KTREXLEVEL_ENVFX_C, 0);
        skyFn_80088e54(1, lbl_803E67A4);
        mainSetBits(0x55e, 1);
        ((GameObject*)obj)->unkF4 = 1;
    }
    lbl_803DDD40 = mainGetBit(0x572);
}

void KT_RexLevel_init(int obj)
{
    char* extra = ((GameObject*)obj)->extra;
    setDrawCloudsAndLights(0);
    mainSetBits(0x572, 0);
    mainSetBits(0x56e, 1);
    mainSetBits(0x566, 1);
    mainSetBits(0x569, 1);
    *(f32*)extra = lbl_803E67A8;
    mainSetBits(0x55a, 1);
    mainSetBits(0x54a, 2);
    mainSetBits(0x54e, 2);
    mainSetBits(0x552, 1);
    mainSetBits(0x556, 1);
    ((GameObject*)obj)->unkF4 = 0;
    mainSetBits(0xefd, 1);
}

void KT_RexLevel_release(void)
{
}

void KT_RexLevel_initialise(void)
{
}
