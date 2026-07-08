/*
 * dummya4 (DLL 0xA4) - empty placeholder DLL.
 *
 * Provides only the three required object-DLL entry points: a no-op
 * release and initialise, plus a func03 stub that returns 0. No game
 * objects, state, or behaviour live here.
 */
#include "main/dll/dll_00A4_dummya4.h"

int DummyA4_func03_ret_0(void)
{
    return 0x0;
}

void DummyA4_release(void)
{
}

void DummyA4_initialise(void)
{
}
