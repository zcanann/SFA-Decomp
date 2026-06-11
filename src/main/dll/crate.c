#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/crate.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80017ac8();
extern void GameBit_Set(int eventId, int value);

#define SFXPLAYER_EVENT_ACTIVATE 1
#define SFXPLAYER_EVENT_DEACTIVATE 2
#define SFXPLAYER_EVENT_VARIANT 3
#define SFXPLAYER_VARIANT_TIMER_FRAMES 0x96
/*
 * --INFO--
 *
 * Function: sfxplayer_updateState
 * EN v1.0 Address: 0x80208098
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_802081e0
 * EN v1.0 Address: 0x802081E0
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8020826C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on

