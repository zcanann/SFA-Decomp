#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/dll/crate.h"

#define SFXPLAYER_EVENT_ACTIVATE 1
#define SFXPLAYER_EVENT_DEACTIVATE 2
#define SFXPLAYER_EVENT_VARIANT 3
#define SFXPLAYER_VARIANT_TIMER_FRAMES 0x96
undefined4 sfxplayer_updateState(int obj, undefined4 unused, ObjAnimUpdateState* animUpdate)
{
    int event;
    SfxplayerState* state;
    int i;

    state = ((GameObject*)obj)->extra;
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    i = 0;
    while (i < (int)animUpdate->eventCount)
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
            case 0x672:
                GameBit_Set(0x66e, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case 0x673:
                GameBit_Set(0x66f, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case 0x674:
                GameBit_Set(0x670, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            case 0x675:
                GameBit_Set(0x9f5, 1);
                state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
        i++;
    }
    return 0;
}
