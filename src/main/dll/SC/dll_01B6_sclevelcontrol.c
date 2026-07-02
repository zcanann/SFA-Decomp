/* DLL 0x01B6 — SC level-control objects [801DAFA4-801DAFDC).
 * Master controller for the LightFoot Village (map "swapcircle", map-event
 * 0xe). Drives the village "mode" that gates which NPCs spawn (see lightfoot
 * objShouldLoad): mode 1->2 when GameBit 0x5f3 is set (water spellstone placed
 * at the Ocean Force Point), mode 2->6 when 0x2d0 is set (totem-bond ceremony
 * complete). Chief/MuscleFoot/throne require mode >=3. Also resets the four
 * totem-pole bits (0x81-0x84) on entry and runs the area fog/music/timers. */
#include "main/dll/sclevelcontrolstate_types.h"
#include "main/game_object.h"
#include "main/dll/CR/CRsnowbike.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"
#include "main/lightmap.h"
#include "main/audio/music_trigger_ids.h"

#define SCLEVELCONTROL_OBJFLAG_PARENT_SLACK 0x1000

STATIC_ASSERT(sizeof(ScLevelControlState) == 0x24);

/* the four LightFoot totem-pole lit-state bits, reset on entry */
#define GAMEBIT_TOTEMPOLE_FRONT 0x81
#define GAMEBIT_TOTEMPOLE_LEFT 0x82
#define GAMEBIT_TOTEMPOLE_RIGHT 0x83
#define GAMEBIT_TOTEMPOLE_REAR 0x84
/* village mode gates */
#define GAMEBIT_WATER_SPELLSTONE_PLACED 0x5f3 /* mode 1 -> 2 */
#define GAMEBIT_TOTEMBOND_COMPLETE 0x2d0      /* mode 2 -> 6 */

extern f32 lbl_803E5554;
extern void objRenderFn_8003b8f4(f32);
extern void gameTimerStop(void);
extern void Music_Trigger(int id, int arg);
extern void gameTimerInit(s8 flags, int minutes);
extern void timerSetToCountUp(void);
extern int isGameTimerDisabled(void);


extern f32 lbl_803E5550;
extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, int f);
extern int mapGetDirIdx(int idx);
extern int unlockLevel(s32 val, int idx, int flag);
extern int getSaveGameLoadStatus(void);
extern f32 lbl_803E5580;
extern f32 lbl_803E5564;
extern f32 lbl_803E5568;
extern f32 lbl_803E5570;
extern f32 lbl_803E5574;
extern f32 lbl_803E5578;
extern f32 lbl_803E557C;
extern void skyFn_80088c94(int flags, int mode);
extern void envFxActFn_800887f8(u8 value);
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern int getEnvfxAct(int a, int b, u16 idx, int d);

extern void gameTextShow(int a);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void warpToMap(int idx, s8 transType);

extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern u16 gScLevelControlMusicStepSequence[4];
extern const f32 lbl_803E5558;
extern f32 lbl_803E555C;
extern f32 lbl_803E5560;
extern f32 lbl_803E556C;

void sc_levelcontrol_hitDetect(void)
{
}

void sc_levelcontrol_release(void)
{
}

void sc_levelcontrol_initialise(void)
{
}

int sc_levelcontrol_getExtraSize(void) { return 0x24; }
int sc_levelcontrol_getObjectTypeId(void) { return 0x0; }

u8 sc_levelcontrol_getAnimEventState(int* obj) { return *(u8*)((char*)(int*)((GameObject*)obj)->extra + 0x1d); }

void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5554);
}

void sc_levelcontrol_free(int obj)
{
    gameTimerStop();
    disableHeavyFog();
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Music_Trigger(MUSICTRIG_Teleport, 0);
    Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
    Music_Trigger(MUSICTRIG_fox_arwing, 0);
    Music_Trigger(MUSICTRIG_trex_chase, 0);
}

int sc_levelcontrol_processAnimEventsCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int state = *(int*)&((GameObject*)obj)->extra;
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
            ((ScLevelControlState*)state)->flags1F |= 2;
            break;
        }
    }
    ((ScLevelControlState*)state)->flags1F |= 1;
    GameBit_Set(0x60f, 0);
    state = *(int*)&((GameObject*)obj)->extra;
    Obj_GetPlayerObject();
    if (((ScLevelControlState*)state)->mode == 5)
    {
        GameBit_Set(0x60f, 1);
        if (isGameTimerDisabled())
        {
            if ((u32)GameBit_Get(0x7a) != 0)
            {
                GameBit_Set(0x85, 1);
            }
            ((ScLevelControlState*)state)->timer10 = lbl_803E5550;
            ((ScLevelControlState*)state)->mode = 0;
            Sfx_PlayFromObject(0, 0x10a);
            Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        }
    }
    return 0;
}

void sc_levelcontrol_applyAnimEventState(int obj, u8 scale)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    u8 v;

    ((ScLevelControlState*)state)->mode = scale;
    v = ((ScLevelControlState*)state)->mode;
    if (v == 2)
    {
        ((ScLevelControlState*)state)->mode = 0;
    }
    else if (v == 5)
    {
        GameBit_Set(0x2b8, 1);
        GameBit_Set(0x4bd, 0);
        GameBit_Set(0x85, 0);
        gameTimerInit(0x1d, 0x96);
        Music_Trigger(MUSICTRIG_CRF_Suspense, 1);
        timerSetToCountUp();
    }
    else if (v == 3)
    {
        gameTimerInit(0x1d, 0x3c);
        ((ScLevelControlState*)state)->mode = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 1);
        timerSetToCountUp();
    }
    else if (v == 6)
    {
        Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
        ((ScLevelControlState*)state)->mode = 0;
        ((ScLevelControlState*)state)->fadeTimer = lbl_803E5550;
        gameTimerStop();
    }
    else if (v == 4)
    {
        ((ScLevelControlState*)state)->mode = 0;
        Music_Trigger(MUSICTRIG_trex_chase, 0);
        gameTimerStop();
    }
}

void sc_levelcontrol_init(int obj)
{
    ScLevelControlState* st = ((GameObject*)obj)->extra;
    int state = (int)st;
    f32 v;

    ((SnowFlags22*)&((ScLevelControlState*)state)->flags22)->bit7 = 0;
    ((ScLevelControlState*)state)->areaCell = 0xff;
    ((ScLevelControlState*)state)->mode = 0;
    ((GameObject*)obj)->animEventCallback = sc_levelcontrol_processAnimEventsCallback;
    GameBit_Set(0x60f, 1);
    GameBit_Set(0x2b8, 0);
    GameBit_Set(0x4bd, 1);
    GameBit_Set(GAMEBIT_TOTEMPOLE_FRONT, 0);
    GameBit_Set(GAMEBIT_TOTEMPOLE_LEFT, 0);
    GameBit_Set(GAMEBIT_TOTEMPOLE_RIGHT, 0);
    GameBit_Set(GAMEBIT_TOTEMPOLE_REAR, 0);
    st->fog0C = lbl_803E5580;
    v = lbl_803E5564;
    st->fogNear = lbl_803E5564;
    st->fog04 = v;
    st->fog08 = lbl_803E5568;
    enableHeavyFog(lbl_803E5570 + st->fogNear, st->fogNear, lbl_803E5574, lbl_803E5578, lbl_803E557C, 0);
    if ((u32)GameBit_Get(0x7a) != 0)
    {
        GameBit_Set(0x85, 1);
    }
    unlockLevel(mapGetDirIdx(0xe), 0, 0);
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    ((GameObject*)obj)->unkF8 = 1;
}

/* Per-frame driver: replays the env-fx set on map (re)entry, advances the
   village mode gates, runs the fade/exit countdown timers, eases the heavy
   fog level, tracks the totem combo code (bits 0x7d..0x7f) into the music
   step, and keeps the area music in sync with the day/night sun position. */
void sc_levelcontrol_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    u8* player = Obj_GetPlayerObject();

    if (((GameObject*)obj)->unkF4 != 0)
    {
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        if (((GameObject*)obj)->unkF4 == 2)
        {
            getEnvfxActImmediately(0, 0, 0x4f, 0);
            getEnvfxActImmediately(0, 0, 0x50, 0);
            getEnvfxActImmediately(0, 0, 0x245, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(0xe, 5) != 0)
            {
                getEnvfxActImmediately(0, 0, 0x246, 0);
            }
            else
            {
                getEnvfxActImmediately(0, 0, 0x51, 0);
            }
        }
        else
        {
            getEnvfxAct(0, 0, 0x4f, 0);
            getEnvfxAct(0, 0, 0x50, 0);
            getEnvfxAct(0, 0, 0x245, 0);
            if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(0xe, 5) != 0)
            {
                getEnvfxAct(0, 0, 0x246, 0);
            }
            else
            {
                getEnvfxAct(0, 0, 0x51, 0);
            }
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    if (((SnowFlags22*)&((ScLevelControlState*)state)->flags22)->bit7 == 0 && (u32)GameBit_Get(0xc53) != 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(0xe, 0xa, 1);
        ((SnowFlags22*)&((ScLevelControlState*)state)->flags22)->bit7 = 1;
    }
    if (((ScLevelControlState*)state)->areaCell != 0xe)
    {
        if (coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ) == 0xe)
        {
            u8 c = ((int (*)(s32))(*gMapEventInterface)->getMapAct)(0xe);
            Obj_GetPlayerObject();
            switch (c)
            {
            case 1:
                if ((u32)GameBit_Get(GAMEBIT_WATER_SPELLSTONE_PLACED) != 0)
                {
                    (*gMapEventInterface)->setMapAct(0xe, 2);
                }
                break;
            case 2:
            case 3:
            case 4:
            case 5:
                if ((u32)GameBit_Get(GAMEBIT_TOTEMBOND_COMPLETE) != 0)
                {
                    (*gMapEventInterface)->setMapAct(0xe, 6);
                }
                break;
            }
        }
        else
        {
            return;
        }
    }
    if (((ScLevelControlState*)state)->fadeTimer != lbl_803E5558 &&
        (((GameObject*)player)->objectFlags & SCLEVELCONTROL_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (lbl_803E5550 == ((ScLevelControlState*)state)->fadeTimer)
        {
            (*gScreenTransitionInterface)->start(0x73, 1);
        }
        ((ScLevelControlState*)state)->fadeTimer -= timeDelta;
        if (((ScLevelControlState*)state)->fadeTimer <= *(f32*)&lbl_803E5558)
        {
            ((ScLevelControlState*)state)->fadeTimer = lbl_803E5558;
            ((ScLevelControlState*)state)->timer10 = lbl_803E5558;
            GameBit_Set(0x2b8, 0);
            GameBit_Set(0x4bd, 1);
            GameBit_Set(GAMEBIT_TOTEMPOLE_FRONT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_LEFT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_RIGHT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_REAR, 0);
            GameBit_Set(0x63e, 1);
            GameBit_Set(0x7cf, 1);
        }
    }
    else if (((ScLevelControlState*)state)->timer10 != *(f32*)&lbl_803E5558 &&
             (((GameObject*)player)->objectFlags & SCLEVELCONTROL_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (lbl_803E5550 == ((ScLevelControlState*)state)->timer10)
        {
            (*gScreenTransitionInterface)->start(0x73, 1);
        }
        ((ScLevelControlState*)state)->timer10 -= timeDelta;
        if (((ScLevelControlState*)state)->timer10 <= *(f32*)&lbl_803E5558)
        {
            GameBit_Set(0x640, 1);
            ((ScLevelControlState*)state)->timer10 = lbl_803E5558;
            GameBit_Set(0x2b8, 0);
            GameBit_Set(0x4bd, 1);
            GameBit_Set(GAMEBIT_TOTEMPOLE_FRONT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_LEFT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_RIGHT, 0);
            GameBit_Set(GAMEBIT_TOTEMPOLE_REAR, 0);
        }
    }
    ((ScLevelControlState*)state)->areaCell = coordsToMapCell(((GameObject*)player)->anim.localPosX,
                                                              ((GameObject*)player)->anim.localPosZ);
    if ((u32)GameBit_Get(0xcdc) != 0)
    {
        if (((ScLevelControlState*)state)->fog0C > lbl_803E5558)
        {
            gameTextShow(0x429);
            ((ScLevelControlState*)state)->fog0C -= timeDelta;
            if (((ScLevelControlState*)state)->fog0C < *(f32*)&lbl_803E5558)
            {
                ((ScLevelControlState*)state)->fog0C = lbl_803E5558;
            }
        }
        if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(0xe, 1) != 0)
        {
            ((ScLevelControlState*)state)->fog04 = lbl_803E555C;
            ((ScLevelControlState*)state)->fog08 = lbl_803E5560;
        }
        else if (((u8 (*)(int, int))(*gMapEventInterface)->getObjGroupStatus)(0xe, 5) != 0)
        {
            ((ScLevelControlState*)state)->fog04 = lbl_803E5564;
            ((ScLevelControlState*)state)->fog08 = lbl_803E5568;
            if (((GameObject*)obj)->unkF8 != 0)
            {
                skyFn_80088e54(1, lbl_803E5554);
                ((GameObject*)obj)->unkF8 = 0;
            }
        }
        else
        {
            ((ScLevelControlState*)state)->fog04 = lbl_803E555C;
            ((ScLevelControlState*)state)->fog08 = lbl_803E5560;
        }
    }
    else
    {
        ((ScLevelControlState*)state)->fog04 = lbl_803E556C;
        ((ScLevelControlState*)state)->fog08 = lbl_803E5568;
    }
    if (((ScLevelControlState*)state)->fog04 != *(f32*)state)
    {
        *(f32*)state = ((ScLevelControlState*)state)->fog08 * timeDelta + *(f32*)state;
        if (((ScLevelControlState*)state)->fog08 < lbl_803E5558)
        {
            if (*(f32*)state < ((ScLevelControlState*)state)->fog04)
            {
                *(f32*)state = ((ScLevelControlState*)state)->fog04;
            }
        }
        else
        {
            if (*(f32*)state > ((ScLevelControlState*)state)->fog04)
            {
                *(f32*)state = ((ScLevelControlState*)state)->fog04;
            }
        }
        enableHeavyFog(lbl_803E5570 + *(f32*)state, *(f32*)state, lbl_803E5574, lbl_803E5578,
                       lbl_803E557C, 0);
    }
    if ((u32)GameBit_Get(0x7d) != 0)
    {
        GameBit_Set(0x7d, 0);
        if (gScLevelControlMusicStepSequence[((ScLevelControlState*)state)->musicStep] == 0x7d)
        {
            ((ScLevelControlState*)state)->musicStep += 1;
        }
        else
        {
            ((ScLevelControlState*)state)->musicStep = 0;
        }
    }
    else if ((u32)GameBit_Get(0x7e) != 0)
    {
        GameBit_Set(0x7e, 0);
        if (gScLevelControlMusicStepSequence[((ScLevelControlState*)state)->musicStep] == 0x7e)
        {
            ((ScLevelControlState*)state)->musicStep += 1;
        }
        else
        {
            ((ScLevelControlState*)state)->musicStep = 0;
        }
    }
    else if ((u32)GameBit_Get(0x7f) != 0)
    {
        GameBit_Set(0x7f, 0);
        if (gScLevelControlMusicStepSequence[((ScLevelControlState*)state)->musicStep] == 0x7f)
        {
            ((ScLevelControlState*)state)->musicStep += 1;
        }
        else
        {
            ((ScLevelControlState*)state)->musicStep = 0;
        }
    }
    if (((ScLevelControlState*)state)->musicStep >= 3)
    {
        GameBit_Set(0x80, 1);
        ((ScLevelControlState*)state)->musicStep = 0;
    }
    if ((((ScLevelControlState*)state)->flags1F & 1) != 0)
    {
        ((ScLevelControlState*)state)->flags1F &= ~1;
        GameBit_Set(0x60f, 1);
        if ((u32)GameBit_Get(0x7a) == 0)
        {
            if ((u32)GameBit_Get(0x627) != 0 && (u32)GameBit_Get(0x63e) != 0)
            {
                GameBit_Set(0x61c, 1);
            }
        }
        else
        {
            if ((u32)GameBit_Get(0x61c) != 0)
            {
                GameBit_Set(0x85, 1);
            }
        }
    }
    if (((ScLevelControlState*)state)->mode == 0)
    {
        if ((u32)GameBit_Get(0x60e) != 0)
        {
            GameBit_Set(0x60e, 0);
            timeListFn_8012df14();
        }
    }
    else if (((ScLevelControlState*)state)->mode == 5)
    {
        if ((u32)GameBit_Get(0x60e) != 0)
        {
            GameBit_Set(0x60e, 0);
            gameTimerStop();
            if ((u32)GameBit_Get(0x7a) != 0)
            {
                GameBit_Set(0x85, 1);
            }
            ((ScLevelControlState*)state)->timer10 = lbl_803E5550;
            (*gScreenTransitionInterface)->start(0x73, 1);
            ((ScLevelControlState*)state)->mode = 0;
            Sfx_PlayFromObject(0, 0x10a);
        }
    }
    if ((u32)GameBit_Get(0x647) != 0)
    {
        GameBit_Set(0x612, 1);
        GameBit_Set(0x90b, 1);
        GameBit_Set(0x87, 1);
    }
    if ((u32)GameBit_Get(0xbde) != 0)
    {
        GameBit_Set(0x2c6, 1);
        GameBit_Set(0x2ce, 1);
        GameBit_Set(0xbdc, 1);
    }
    if ((u32)GameBit_Get(0xbe5) != 0)
    {
        GameBit_Set(0xbdf, 1);
        GameBit_Set(0xbe1, 1);
        GameBit_Set(0xbe3, 1);
    }
    {
        int state2 = *(int*)&((GameObject*)obj)->extra;
        Obj_GetPlayerObject();
        if (((ScLevelControlState*)state2)->mode == 5)
        {
            GameBit_Set(0x60f, 1);
            if (isGameTimerDisabled())
            {
                if ((u32)GameBit_Get(0x7a) != 0)
                {
                    GameBit_Set(0x85, 1);
                }
                ((ScLevelControlState*)state2)->timer10 = lbl_803E5550;
                ((ScLevelControlState*)state2)->mode = 0;
                Sfx_PlayFromObject(0, 0x10a);
                Music_Trigger(MUSICTRIG_CRF_Suspense, 0);
            }
        }
    }
    if ((u32)GameBit_Get(0x4d0) == 0)
    {
        if ((u32)GameBit_Get(0x2b5) != 0)
        {
            GameBit_Set(0x4d0, 1);
            (*gMapEventInterface)->setObjGroupStatus(0xe, 2, 1);
            warpToMap(0x50, 0);
            (*gMapEventInterface)->setObjGroupStatus(0xe, 1, 0);
        }
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (((ScLevelControlState*)state)->musicTrack != 0x2d)
        {
            ((ScLevelControlState*)state)->musicTrack = 0x2d;
            Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
        }
        if (((ScLevelControlState*)state)->ambientMusicTrack != -1)
        {
            ((ScLevelControlState*)state)->ambientMusicTrack = -1;
            Music_Trigger(MUSICTRIG_fox_arwing, 0);
        }
    }
    else
    {
        if (((ScLevelControlState*)state)->musicTrack != 0x33)
        {
            ((ScLevelControlState*)state)->musicTrack = 0x33;
            Music_Trigger(MUSICTRIG_KP_Text, 1);
        }
        if (((ScLevelControlState*)state)->ambientMusicTrack != 0x22)
        {
            ((ScLevelControlState*)state)->ambientMusicTrack = 0x22;
            Music_Trigger(MUSICTRIG_fox_arwing, 1);
        }
    }
    SCGameBitLatch_Update(state + 0x18, 1, -1, -1, 0xe1e, 0x36);
    SCGameBitLatch_Update(state + 0x18, 2, -1, -1, 0xcbb, 0xc4);
    if ((((ScLevelControlState*)state)->flags1F & 2) != 0)
    {
        GameBit_Set(0x60e, 1);
        ((ScLevelControlState*)state)->flags1F &= ~2;
    }
}
