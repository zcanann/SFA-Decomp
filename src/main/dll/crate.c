/*
 * sfxplayer object - animation-sequence event handler.
 *
 * Bound as an object's animEventCallback; each tick it walks the
 * pending sequence-event list (animUpdate->eventIds) and drives the
 * effect's audio game bits off the object's effectSfxBaseId:
 *   ACTIVATE   -> sets bit (base + 5)
 *   DEACTIVATE -> clears bit (base + 5) and flags the effect finished
 *   VARIANT    -> for the four known base ids (0x672..0x675) sets the
 *                 paired variant bit and arms a 0x96-frame variant timer
 * Each event is consumed (zeroed) as it is processed.
 */
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/crate.h"

#define SFXPLAYER_EVENT_ACTIVATE 1
#define SFXPLAYER_EVENT_DEACTIVATE 2
#define SFXPLAYER_EVENT_VARIANT 3
#define SFXPLAYER_VARIANT_TIMER_FRAMES 0x96

#define SFXPLAYER_BASE_VARIANT_A 0x672
#define SFXPLAYER_BASE_VARIANT_B 0x673
#define SFXPLAYER_BASE_VARIANT_C 0x674
#define SFXPLAYER_BASE_VARIANT_D 0x675

#define GAMEBIT_SFXPLAYER_VARIANT_A 0x66e
#define GAMEBIT_SFXPLAYER_VARIANT_B 0x66f
#define GAMEBIT_SFXPLAYER_VARIANT_C 0x670
#define GAMEBIT_SFXPLAYER_VARIANT_D 0x9f5

u32 sfxplayer_updateState(int obj, u32 unused, ObjAnimUpdateState* animUpdate)
{
    int event;
    SfxplayerState* state;
    int i;

    state = ((GameObject*)obj)->extra;
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        switch (event)
        {
        case SFXPLAYER_EVENT_ACTIVATE:
            GameBit_Set(state->effectSfxBaseId + 5, 1);
            break;
        case SFXPLAYER_EVENT_DEACTIVATE:
            GameBit_Set(state->effectSfxBaseId + 5, 0);
            state->effectFlags = 1;
            break;
        case SFXPLAYER_EVENT_VARIANT:
            switch (state->effectSfxBaseId)
            {
            case SFXPLAYER_BASE_VARIANT_A:
                GameBit_Set(GAMEBIT_SFXPLAYER_VARIANT_A, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case SFXPLAYER_BASE_VARIANT_B:
                GameBit_Set(GAMEBIT_SFXPLAYER_VARIANT_B, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case SFXPLAYER_BASE_VARIANT_C:
                GameBit_Set(GAMEBIT_SFXPLAYER_VARIANT_C, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case SFXPLAYER_BASE_VARIANT_D:
                GameBit_Set(GAMEBIT_SFXPLAYER_VARIANT_D, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}
