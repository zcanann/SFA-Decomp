/*
 * EdibleMushroom_SeqFn (DLL fragment at 0x801D0828) - the animation
 * sequence callback for the edible mushroom enemy object. Registered as
 * the object's animEventCallback (see dll_01A7_ediblemushroom.c) and
 * invoked when its trigger sequence fires; it flags the per-object
 * EdibleMushroomState so the main update can run its sequence reset.
 */
#include "main/game_object.h"
#include "main/dll/ediblemushroom.h"

int EdibleMushroom_SeqFn(int* obj)
{
    EdibleMushroomState* state = ((GameObject*)obj)->extra;
    state->seqResetPending = 1;
    return 0;
}
