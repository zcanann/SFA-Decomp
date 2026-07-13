/*
 * dummy3a (DLL 0x3A) - a stub game object. Exports, in source/symbol order:
 * render, frameEnd (empty voids), frameStart (the sole non-void stub, which
 * simply returns 0), then release and initialise (empty voids). The object
 * does nothing per frame.
 */
#include "types.h"
#include "main/dll/dll_003A_dummy3a.h"

void Dummy3A_render(void)
{
}

void Dummy3A_frameEnd(void)
{
}

int Dummy3A_frameStart(void)
{
    return 0;
}

void Dummy3A_release(void)
{
}

void Dummy3A_initialise(void)
{
}

u32 lbl_8031ADF8[10] = {0x00000000, 0x00000000, 0x00000000, 0x00050000,
        (u32)Dummy3A_initialise, (u32)Dummy3A_release,
        0x00000000, (u32)Dummy3A_frameStart, (u32)Dummy3A_frameEnd,
        (u32)Dummy3A_render};
