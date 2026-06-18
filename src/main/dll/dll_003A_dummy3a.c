/*
 * dummy3a (DLL 0x3A) - a stub game object. Exports, in source/symbol order:
 * render, frameEnd, release, initialise (all empty voids) and frameStart,
 * the sole non-void stub, which simply returns 0. The object does nothing
 * per frame.
 */

void Dummy3A_render(void)
{
}

void Dummy3A_frameEnd(void)
{
}

void Dummy3A_release(void)
{
}

void Dummy3A_initialise(void)
{
}

int Dummy3A_frameStart(void) { return 0; }
