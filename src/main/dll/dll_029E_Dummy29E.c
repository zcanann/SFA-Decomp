#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

int Dummy29E_getExtraSize(void) { return 0x0; }

int Dummy29E_getObjectTypeId(void) { return 0x0; }

void Dummy29E_free(void) {}

void Dummy29E_render(void) {}

void Dummy29E_hitDetect(void) {}

void Dummy29E_update(void) {}

void Dummy29E_init(void) {}

void Dummy29E_release(void) {}

void Dummy29E_initialise(void) {}

#pragma scheduling off
void fn_8022F558(int obj, int v)
{
    ARWBombCollState *state = ((GameObject *)obj)->extra;
    state->lifetime = (f32)v;
}
#pragma scheduling reset
