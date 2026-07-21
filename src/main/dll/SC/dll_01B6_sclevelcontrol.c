/* DLL 0x01B6 - SC level-control objects [801DAFA4-801DAFDC).
 * Master controller for the LightFoot Village (map "swapcircle", map-event
 * 0xe). Drives the village "mode" that gates which NPCs spawn (see lightfoot
 * objShouldLoad): mode 1->2 when GameBit 0x5f3 is set (water spellstone placed
 * at the Ocean Force Point), mode 2->6 when 0x2d0 is set (totem-bond ceremony
 * complete). Chief/MuscleFoot/throne require mode >=3. Also resets the four
 * totem-pole bits (0x81-0x84) on entry and runs the area fog/music/timers. */
#include "main/dll/sclevelcontrolstate_types.h"
#include "main/dll/savegame_load_api.h"
#include "main/game_timer_control_api.h"
#include "main/gametext_show_api.h"
#include "main/audio/music_api.h"
#include "main/object_render.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/map_load.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/object_api.h"
#include "main/dll/SC/dll_01B6_sclevelcontrol.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/sky_api.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/frame_timing.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/lightmap_api.h"
#include "main/audio/music_trigger_ids.h"

u16 gScLevelControlMusicStepSequence[4] = {0x7D, 0x7E, 0x7F, 0};

#define SCLEVELCONTROL_OBJFLAG_PARENT_SLACK 0x1000

/* map-event id of the LightFoot Village map ("swapcircle"); see docblock */
#define SCLEVELCONTROL_MAP_SWAPCIRCLE 0xe

STATIC_ASSERT(sizeof(ScLevelControlState) == 0x24);

/* the four LightFoot totem-pole lit-state bits, reset on entry */
#define GAMEBIT_TOTEMPOLE_FRONT 0x81
#define GAMEBIT_TOTEMPOLE_LEFT 0x82
#define GAMEBIT_TOTEMPOLE_RIGHT 0x83
#define GAMEBIT_TOTEMPOLE_REAR 0x84
/* village mode gates */
#define GAMEBIT_WATER_SPELLSTONE_PLACED 0x5f3 /* mode 1 -> 2 */
#define GAMEBIT_TOTEMBOND_COMPLETE 0x2d0      /* mode 2 -> 6 */

/* env-effect ids replayed on map (re)entry (index-style; roles opaque).
   D vs E is selected by the map-event 0xe / objgroup 5 status. */
#define SCLEVELCONTROL_ENVFX_A 0x4f
#define SCLEVELCONTROL_ENVFX_B 0x50
#define SCLEVELCONTROL_ENVFX_C 0x245
#define SCLEVELCONTROL_ENVFX_D 0x246
#define SCLEVELCONTROL_ENVFX_E 0x51


int sc_levelcontrol_processAnimEventsCallback(GameObject *obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ScLevelControlState* state = (obj)->extra;
    int i;

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(u32)animUpdate->eventCount; i++)
    {
        int eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case 1:
            sc_levelcontrol_applyAnimEventState(obj, 7);
            break;
        case 2:
            sc_levelcontrol_applyAnimEventState(obj, 5);
            break;
        case 3:
            state->flags1F |= 2;
            break;
        }
    }
    state->flags1F |= 1;
    mainSetBits(0x60f, 0);
    state = (obj)->extra;
    Obj_GetPlayerObject();
    if (state->mode == 5)
    {
        mainSetBits(0x60f, 1);
        if (isGameTimerDisabled())
        {
            if ((u32)mainGetBit(0x7a) != 0)
            {
                mainSetBits(0x85, 1);
            }
            state->timer10 = 120.0f;
            state->mode = 0;
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
            Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        }
    }
    return 0;
}

u8 sc_levelcontrol_getAnimEventState(int* obj) { return ((ScLevelControlState*)((GameObject*)obj)->extra)->mode; }

void sc_levelcontrol_applyAnimEventState(GameObject *obj, u8 scale)
{
    ScLevelControlState* state = (obj)->extra;
    u8 mode;

    state->mode = scale;
    mode = state->mode;
    if (mode == 2)
    {
        state->mode = 0;
    }
    else if (mode == 5)
    {
        mainSetBits(0x2b8, 1);
        mainSetBits(0x4bd, 0);
        mainSetBits(0x85, 0);
        gameTimerInit(0x1d, 0x96);
        Music_Trigger(MUSICTRIG_CRF_Suspense, 1);
        timerSetToCountUp();
    }
    else if (mode == 3)
    {
        gameTimerInit(0x1d, 0x3c);
        state->mode = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 1);
        timerSetToCountUp();
    }
    else if (mode == 6)
    {
        Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        state->mode = 0;
        state->fadeTimer = 120.0f;
        gameTimerStop();
    }
    else if (mode == 4)
    {
        state->mode = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 0);
        gameTimerStop();
    }
}

int sc_levelcontrol_getExtraSize(void) { return 0x24; }
int sc_levelcontrol_getObjectTypeId(void) { return 0x0; }

void sc_levelcontrol_free(GameObject *obj)
{
    gameTimerStop();
    disableHeavyFog();
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Music_Trigger(MUSICTRIG_Teleport, 0);
    Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
    Music_Trigger(MUSICTRIG_fox_arwing, 0);
    Music_Trigger(MUSICTRIG_trex_chase, 0);
}

void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((GameObject*)p1, p2, p3, p4, p5, 1.0f);
}

void sc_levelcontrol_hitDetect(void)
{
}

/* Per-frame driver: replays the env-fx set on map (re)entry, advances the
   village mode gates, runs the fade/exit countdown timers, eases the heavy
   fog level, tracks the totem combo code (bits 0x7d..0x7f) into the music
   step, and keeps the area music in sync with the day/night sun position. */
void sc_levelcontrol_update(GameObject *obj)
{
    ScLevelControlState* state = (obj)->extra;
    GameObject* player = Obj_GetPlayerObject();

    if ((obj)->userData1 != 0)
    {
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        if ((obj)->userData1 == 2)
        {
            getEnvfxActImmediately(0, 0, SCLEVELCONTROL_ENVFX_A, 0);
            getEnvfxActImmediately(0, 0, SCLEVELCONTROL_ENVFX_B, 0);
            getEnvfxActImmediately(0, 0, SCLEVELCONTROL_ENVFX_C, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SCLEVELCONTROL_MAP_SWAPCIRCLE, 5) != 0)
            {
                getEnvfxActImmediately(0, 0, SCLEVELCONTROL_ENVFX_D, 0);
            }
            else
            {
                getEnvfxActImmediately(0, 0, SCLEVELCONTROL_ENVFX_E, 0);
            }
        }
        else
        {
            getEnvfxAct(0, 0, SCLEVELCONTROL_ENVFX_A, 0);
            getEnvfxAct(0, 0, SCLEVELCONTROL_ENVFX_B, 0);
            getEnvfxAct(0, 0, SCLEVELCONTROL_ENVFX_C, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SCLEVELCONTROL_MAP_SWAPCIRCLE, 5) != 0)
            {
                getEnvfxAct(0, 0, SCLEVELCONTROL_ENVFX_D, 0);
            }
            else
            {
                getEnvfxAct(0, 0, SCLEVELCONTROL_ENVFX_E, 0);
            }
        }
        (obj)->userData1 = 0;
    }
    if (((SnowFlags22*)&state->flags22)->bit7 == 0 && (u32)mainGetBit(GAMEBIT_LV_ChallengeGate2Complete) != 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(SCLEVELCONTROL_MAP_SWAPCIRCLE, 0xa, 1);
        ((SnowFlags22*)&state->flags22)->bit7 = 1;
    }
    if (state->areaCell != 0xe)
    {
        if (coordsToMapCell(player->anim.localPosX, player->anim.localPosZ) == 0xe)
        {
            u8 c = ((int (*)(s32))(*gMapEventInterface)->getMapAct)(SCLEVELCONTROL_MAP_SWAPCIRCLE);
            Obj_GetPlayerObject();
            switch (c)
            {
            case 1:
                if ((u32)mainGetBit(GAMEBIT_WATER_SPELLSTONE_PLACED) != 0)
                {
                    (*gMapEventInterface)->setMapAct(SCLEVELCONTROL_MAP_SWAPCIRCLE, 2);
                }
                break;
            case 2:
            case 3:
            case 4:
            case 5:
                if ((u32)mainGetBit(GAMEBIT_TOTEMBOND_COMPLETE) != 0)
                {
                    (*gMapEventInterface)->setMapAct(SCLEVELCONTROL_MAP_SWAPCIRCLE, 6);
                }
                break;
            }
        }
        else
        {
            return;
        }
    }
    if (state->fadeTimer &&
        (player->objectFlags & SCLEVELCONTROL_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (120.0f == state->fadeTimer)
        {
            (*gScreenTransitionInterface)->start(0x73, 1);
        }
        state->fadeTimer -= timeDelta;
        if (state->fadeTimer <= 0.0f)
        {
            state->fadeTimer = 0.0f;
            state->timer10 = 0.0f;
            mainSetBits(0x2b8, 0);
            mainSetBits(0x4bd, 1);
            mainSetBits(GAMEBIT_TOTEMPOLE_FRONT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_LEFT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_RIGHT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_REAR, 0);
            mainSetBits(0x63e, 1);
            mainSetBits(0x7cf, 1);
        }
    }
    else if (state->timer10 &&
             (player->objectFlags & SCLEVELCONTROL_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (120.0f == state->timer10)
        {
            (*gScreenTransitionInterface)->start(0x73, 1);
        }
        state->timer10 -= timeDelta;
        if (state->timer10 <= 0.0f)
        {
            mainSetBits(0x640, 1);
            state->timer10 = 0.0f;
            mainSetBits(0x2b8, 0);
            mainSetBits(0x4bd, 1);
            mainSetBits(GAMEBIT_TOTEMPOLE_FRONT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_LEFT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_RIGHT, 0);
            mainSetBits(GAMEBIT_TOTEMPOLE_REAR, 0);
        }
    }
    state->areaCell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
    if ((u32)mainGetBit(0xcdc) != 0)
    {
        if (state->fog0C > 0.0f)
        {
            gameTextShow(0x429);
            state->fog0C -= timeDelta;
            if (state->fog0C < 0.0f)
            {
                state->fog0C = 0.0f;
            }
        }
        if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SCLEVELCONTROL_MAP_SWAPCIRCLE, 1) != 0)
        {
            state->fog04 = -1000.0f;
            state->fog08 = 0.35f;
        }
        else if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(SCLEVELCONTROL_MAP_SWAPCIRCLE, 5) != 0)
        {
            state->fog04 = -1200.0f;
            state->fog08 = -0.35f;
            if ((obj)->userData2 != 0)
            {
                skyFn_80088e54(1, 1.0f);
                (obj)->userData2 = 0;
            }
        }
        else
        {
            state->fog04 = -1000.0f;
            state->fog08 = 0.35f;
        }
    }
    else
    {
        state->fog04 = -1080.0f;
        state->fog08 = -0.35f;
    }
    if (state->fog04 != state->fogNear)
    {
        state->fogNear = state->fog08 * timeDelta + state->fogNear;
        if (state->fog08 < 0.0f)
        {
            if (state->fogNear < state->fog04)
            {
                state->fogNear = state->fog04;
            }
        }
        else
        {
            if (state->fogNear > state->fog04)
            {
                state->fogNear = state->fog04;
            }
        }
        enableHeavyFog(50.0f + state->fogNear, state->fogNear, 1000.0f, 0.1f,
                       0.0005f, 0);
    }
    if ((u32)mainGetBit(0x7d) != 0)
    {
        mainSetBits(0x7d, 0);
        if (gScLevelControlMusicStepSequence[state->musicStep] == 0x7d)
        {
            state->musicStep += 1;
        }
        else
        {
            state->musicStep = 0;
        }
    }
    else if ((u32)mainGetBit(0x7e) != 0)
    {
        mainSetBits(0x7e, 0);
        if (gScLevelControlMusicStepSequence[state->musicStep] == 0x7e)
        {
            state->musicStep += 1;
        }
        else
        {
            state->musicStep = 0;
        }
    }
    else if ((u32)mainGetBit(0x7f) != 0)
    {
        mainSetBits(0x7f, 0);
        if (gScLevelControlMusicStepSequence[state->musicStep] == 0x7f)
        {
            state->musicStep += 1;
        }
        else
        {
            state->musicStep = 0;
        }
    }
    if (state->musicStep >= 3)
    {
        mainSetBits(0x80, 1);
        state->musicStep = 0;
    }
    if ((state->flags1F & 1) != 0)
    {
        state->flags1F &= ~1;
        mainSetBits(0x60f, 1);
        if ((u32)mainGetBit(0x7a) == 0)
        {
            if ((u32)mainGetBit(0x627) != 0 && (u32)mainGetBit(0x63e) != 0)
            {
                mainSetBits(GAMEBIT_LV_DoneTests, 1);
            }
        }
        else
        {
            if ((u32)mainGetBit(GAMEBIT_LV_DoneTests) != 0)
            {
                mainSetBits(0x85, 1);
            }
        }
    }
    if (state->mode == 0)
    {
        if ((u32)mainGetBit(0x60e) != 0)
        {
            mainSetBits(0x60e, 0);
            timeListFn_8012df14();
        }
    }
    else if (state->mode == 5)
    {
        if ((u32)mainGetBit(0x60e) != 0)
        {
            mainSetBits(0x60e, 0);
            gameTimerStop();
            if ((u32)mainGetBit(0x7a) != 0)
            {
                mainSetBits(0x85, 1);
            }
            state->timer10 = 120.0f;
            (*gScreenTransitionInterface)->start(0x73, 1);
            state->mode = 0;
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
        }
    }
    if ((u32)mainGetBit(GAMEBIT_ITEM_LVBlock2_Used) != 0)
    {
        mainSetBits(0x612, 1);
        mainSetBits(0x90b, 1);
        mainSetBits(0x87, 1);
    }
    if ((u32)mainGetBit(GAMEBIT_ITEM_LVBlock3_Used) != 0)
    {
        mainSetBits(0x2c6, 1);
        mainSetBits(0x2ce, 1);
        mainSetBits(0xbdc, 1);
    }
    if ((u32)mainGetBit(GAMEBIT_ITEM_LVBlock1_Used) != 0)
    {
        mainSetBits(0xbdf, 1);
        mainSetBits(0xbe1, 1);
        mainSetBits(0xbe3, 1);
    }
    {
        ScLevelControlState* state2 = (obj)->extra;
        Obj_GetPlayerObject();
        if (state2->mode == 5)
        {
            mainSetBits(0x60f, 1);
            if (isGameTimerDisabled())
            {
                if ((u32)mainGetBit(0x7a) != 0)
                {
                    mainSetBits(0x85, 1);
                }
                state2->timer10 = 120.0f;
                state2->mode = 0;
                Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
            }
        }
    }
    if ((u32)mainGetBit(0x4d0) == 0)
    {
        if ((u32)mainGetBit(GAMEBIT_LV_CapturedByLightFoot) != 0)
        {
            mainSetBits(0x4d0, 1);
            (*gMapEventInterface)->setObjGroupStatus(SCLEVELCONTROL_MAP_SWAPCIRCLE, 2, 1);
            warpToMap(0x50, 0);
            (*gMapEventInterface)->setObjGroupStatus(SCLEVELCONTROL_MAP_SWAPCIRCLE, 1, 0);
        }
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (state->musicTrack != 0x2d)
        {
            state->musicTrack = 0x2d;
            Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
        }
        if (state->ambientMusicTrack != -1)
        {
            state->ambientMusicTrack = -1;
            Music_Trigger(MUSICTRIG_fox_arwing, 0);
        }
    }
    else
    {
        if (state->musicTrack != 0x33)
        {
            state->musicTrack = 0x33;
            Music_Trigger(MUSICTRIG_KP_Text, 1);
        }
        if (state->ambientMusicTrack != 0x22)
        {
            state->ambientMusicTrack = 0x22;
            Music_Trigger(MUSICTRIG_fox_arwing, 1);
        }
    }
    SCGameBitLatch_Update((SCGameBitLatchState*)&state->gameBitLatches, 1, -1, -1, 0xe1e, 0x36);
    SCGameBitLatch_Update((SCGameBitLatchState*)&state->gameBitLatches, 2, -1, -1, 0xcbb, 0xc4);
    if ((state->flags1F & 2) != 0)
    {
        mainSetBits(0x60e, 1);
        state->flags1F &= ~2;
    }
}

void sc_levelcontrol_init(GameObject *obj)
{
    ScLevelControlState* st = (obj)->extra;
    f32 fogNear;

    ((SnowFlags22*)&st->flags22)->bit7 = 0;
    st->areaCell = 0xff;
    st->mode = 0;
    (obj)->animEventCallback = sc_levelcontrol_processAnimEventsCallback;
    mainSetBits(0x60f, 1);
    mainSetBits(0x2b8, 0);
    mainSetBits(0x4bd, 1);
    mainSetBits(GAMEBIT_TOTEMPOLE_FRONT, 0);
    mainSetBits(GAMEBIT_TOTEMPOLE_LEFT, 0);
    mainSetBits(GAMEBIT_TOTEMPOLE_RIGHT, 0);
    mainSetBits(GAMEBIT_TOTEMPOLE_REAR, 0);
    st->fog0C = 300.0f;
    fogNear = -1200.0f;
    st->fogNear = -1200.0f;
    st->fog04 = fogNear;
    st->fog08 = -0.35f;
    enableHeavyFog(50.0f + st->fogNear, st->fogNear, 1000.0f, 0.1f, 0.0005f, 0);
    if ((u32)mainGetBit(0x7a) != 0)
    {
        mainSetBits(0x85, 1);
    }
    unlockLevel(mapGetDirIdx(SCLEVELCONTROL_MAP_SWAPCIRCLE), 0, 0);
    if (getSaveGameLoadStatus() != 0)
    {
        (obj)->userData1 = 2;
    }
    else
    {
        (obj)->userData1 = 1;
    }
    (obj)->userData2 = 1;
}

void sc_levelcontrol_release(void)
{
}

void sc_levelcontrol_initialise(void)
{
}
