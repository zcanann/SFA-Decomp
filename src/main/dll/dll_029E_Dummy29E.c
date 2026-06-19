/*
 * Dummy29E (DLL 0x29E) - an empty object-class slot. Every entry point
 * (extra-size, type-id, init/update/render/hitDetect/free, and the
 * (de)initialise pair) is a stub: no per-object state is allocated and no
 * behaviour runs. The DLL exists only to fill the 0x29E id in the object
 * table.
 *
 * fn_8022F558 is the odd one out: it is the ARWBombColl lifetime setter,
 * called from arwarwing (DLL 0x29A) and andross (DLL 0x2BC), and lives
 * here purely because of where it landed in the link order.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

int Dummy29E_getExtraSize(void) { return 0x0; }

int Dummy29E_getObjectTypeId(void) { return 0x0; }

void Dummy29E_free(void)
{
}

void Dummy29E_render(void)
{
}

void Dummy29E_hitDetect(void)
{
}

void Dummy29E_update(void)
{
}

void Dummy29E_init(void)
{
}

void Dummy29E_release(void)
{
}

void Dummy29E_initialise(void)
{
}

void fn_8022F558(int obj, int lifetime)
{
    ARWBombCollState* state = ((GameObject*)obj)->extra;
    state->lifetime = lifetime;
}
