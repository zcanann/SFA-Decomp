#include "main/effect_interfaces.h"
#include "main/dll/pickup.h"

/* Trivial 4b 0-arg blr leaves. */

void DummyA4_release(void)
{
}

void DummyA4_initialise(void)
{
}

void dll_A5_func01_nop(void);

/* 8b "li r3, N; blr" returners. */
int DummyA4_func03_ret_0(void) { return 0x0; }
