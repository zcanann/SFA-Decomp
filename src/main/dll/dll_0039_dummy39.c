/*
 * dummy39 (DLL 0x39) - a transient UI/transition stub.
 *
 * On init it primes a 0x28-frame (40) countdown in lbl_803DD728; each
 * run() tick decrements it by the elapsed step count (clamped to 3
 * frames). When the countdown reaches zero it loads UI DLL 1 and warps
 * the player to map 0x60, spawn 1. render/frameEnd are no-ops; release
 * frees the cached texture handle (lbl_803DD72C).
 */
#include "types.h"
#include "main/engine_shared.h"
#include "main/texture.h"
extern u8 lbl_803DD728;
extern u8* lbl_803DD72C;

extern void warpToMap(int idx, s8 transType);


#define DUMMY39_COUNTDOWN_FRAMES 0x28
#define DUMMY39_WARP_MAP 0x60
#define DUMMY39_MAX_STEP_FRAMES 3

void Dummy39_render(void)
{
}

void Dummy39_frameEnd(void)
{
}

#pragma scheduling off
#pragma peephole off
int Dummy39_run(void)
{
    s32 step;
    u8 cur;
    s8 next;
    Obj_GetPlayerObject();
    step = framesThisStep;
    if (step > DUMMY39_MAX_STEP_FRAMES) step = DUMMY39_MAX_STEP_FRAMES;
    cur = lbl_803DD728;
    if ((s8)cur > 0)
    {
        next = cur - step;
        *(s8*)&lbl_803DD728 = next;
        if ((s8)(u8)next <= 0)
        {
            loadUiDll(1);
            warpToMap(DUMMY39_WARP_MAP, 1);
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

void Dummy39_release(void) { textureFree(lbl_803DD72C); }

void Dummy39_initialise(void) { lbl_803DD728 = DUMMY39_COUNTDOWN_FRAMES; }
