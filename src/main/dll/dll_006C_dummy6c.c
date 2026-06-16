/*
 * dummy6c (DLL 0x6C) - empty placeholder DLL.
 *
 * Provides only the three required object-DLL entry points: a no-op
 * release and initialise, plus a func03 stub that returns 0. No game
 * objects, state, or behaviour live here.
 */

int Dummy6C_func03_ret_0(void) { return 0x0; }

void Dummy6C_release(void)
{
}

void Dummy6C_initialise(void)
{
}
