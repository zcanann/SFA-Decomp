#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/dll_01A1_nwmammoth.h"
#include "main/screen_transition.h"
#include "main/dll/dim2conveyor.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/gameplay_runtime.h"
#include "main/curve.h"
#include "main/sky_interface.h"
#include "main/dll/player_target.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#define NWMAMMOTH_OBJFLAG_PARENT_SLACK 0x1000
#define NWMAMMOTH_OBJFLAG_RENDERED 0x800
enum NwMammothRuntimeFlag
{
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};
extern u32 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern u32 objAudioFn_8006ef38();

#pragma scheduling on
#pragma peephole on
extern f32 timeDelta;
extern f32 lbl_803E520C;
extern f32 lbl_803E5218;
extern f32 oneOverTimeDelta;
extern f32 gNwMammothPathAccel;
extern f32 gNwMammothPathSpeedMin;
extern f32 gNwMammothPlayerNearDistSq;
extern f32 gNwMammothPathDecel;
extern f32 gNwMammothPathSpeedMax;
extern f32 lbl_803E5250;
extern u8 lbl_803DBF80[4];
extern u8 lbl_803DBF84[4];
extern u8 lbl_803DBF88[4];
extern u8 lbl_803DBF8C[4];
extern u8 lbl_803DBF90[4];
extern u8 lbl_803DBF94[4];
extern u8 lbl_803DBF98[4];
extern u8 lbl_803DBF9C[4];
extern u8 lbl_803DBFA0[4];
extern u8 lbl_803DBFA4[4];
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 x);
extern f32 gNwMammothSfxInterval;
extern f32 gNwMammothTumbleweedDistSqThreshold;
extern f32 gNwMammothCaptureDist;
extern f32 gNwMammothAirMeterFull;
extern f32 gNwMammothAirMeterPerSegment;
extern u8 lbl_803DBFA8[4];
extern u8 lbl_803DBFAC[4];
extern u8 lbl_803DBFB0[4];
extern int gNwMammothBushObjectIds[];
extern int gNwMammothBushGameBits[];
extern int* ObjList_FindObjectById(int id);
extern void fn_8014C66C(int* o, int* target);
extern int* tumbleweedbush_findNearestActive(void* pos);
extern f32 getXZDistance(void* a, void* b);
extern void fn_80163980(int o);
extern void Obj_FreeObject(int o);
extern f32 lbl_803E5210;
extern u32 ObjGroup_AddObject();
extern int ObjTrigger_IsSetById(int obj, int triggerId);
extern void fn_8003A168(int obj, void* p);
extern void characterDoEyeAnims(int obj, void* p);
extern int cMenuGetSelectedItem(void);
extern void fn_801CDF94(int obj, void* state, int flag);
extern u8 gNwMammothTables[];
extern u8 gNwMammothPathSetupDataA[];
extern u8 gNwMammothPathSetupDataB[];
extern NwMammothPathControlInterface** gPathControlInterface;
extern u32 lbl_803E5208;
extern f32 lbl_803E5254;
extern f32 gNwMammothDefaultAnimStepScale;

int nw_mammoth_getExtraSize(void)
{
    return 0x48c;
}

#pragma scheduling off
#pragma peephole off
void fn_801CEE0C(int obj, int p2)
{
    extern int fn_801CE078(int, int);
    extern int gameBitDecrement(int bit);
    extern u8 lbl_803DBF70[4];
    extern u8 lbl_803DBF74[4];
    extern u8 lbl_803DBF78[4];
    extern u8 lbl_803DBF7C[4];
    NwMammothState* state = (NwMammothState*)p2;

    if (fn_801CE078(obj, p2) != 0) return;

    switch (state->stateIndex)
    {
    case 0:
        state->triggerList = lbl_803DBF70;
        if (GameBit_Get(211) != 0)
        {
            state->stateIndex = 1;
        }
        break;
    case 1:
        state->triggerList = lbl_803DBF74;
        switch (GameBit_Get(1400))
        {
        case 0:
            if (ObjTrigger_IsSetById(obj, 1398) != 0)
            {
                GameBit_Set(1400, 1);
                gameBitDecrement(1398);
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
                state->stateIndex = 2;
            }
            break;
        case 1:
            state->stateIndex = 2;
            break;
        default:
            state->stateIndex = 3;
            break;
        }
        break;
    case 2:
        state->triggerList = lbl_803DBF78;
        if (ObjTrigger_IsSetById(obj, 1398) != 0)
        {
            GameBit_Set(1400, 2);
            gameBitDecrement(1398);
            (*gObjectTriggerInterface)->runSequence(4, (void*)obj, -1);
            state->stateIndex = 3;
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
        }
        break;
    case 3:
        state->triggerList = lbl_803DBF7C;
        break;
    }
}

void fn_801CED2C(int obj, int p2)
{
    extern u8 lbl_803DBFB4[4];
    extern u8 lbl_803DBFB8[4];
    extern u8 lbl_803DBFBC[4];
    NwMammothState* state = (NwMammothState*)p2;

    switch (state->stateIndex)
    {
    case 4:
        state->triggerList = lbl_803DBFB4;
        if (ObjTrigger_IsSetById(obj, 418) != 0)
        {
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
            GameBit_Set(413, 1);
            GameBit_Set(419, 1);
            GameBit_Set(3813, 1);
            GameBit_Set(3814, 1);
            state->stateIndex = 5;
        }
        break;
    case 5:
        state->triggerList = lbl_803DBFB8;
        if (GameBit_Get(415) != 0)
        {
            state->stateIndex = 6;
        }
        break;
    case 6:
        state->triggerList = lbl_803DBFBC;
        break;
    }
}

typedef struct
{
    u8 pad[0xc];
    f32 pos[3];
} WoPartfxBlock;

int fn_801CE078(int* obj, u8* st)
{
    u8 night;
    int animCue;
    f32 sunTime;
    WoPartfxBlock blk;
    NwMammothState* state = (NwMammothState*)st;

    night = (u8)(*gSkyInterface)->getSunPosition(&sunTime);
    if (state->animEvents.triggerCount != 0)
    {
        animCue = state->animEvents.triggeredIds[0] == 0;
    }
    else
    {
        animCue = 0;
    }
    if (state->stateIndex < 0x14)
    {
        if (night != 0)
        {
            if (state->pathSpeed > lbl_803E520C)
            {
                return -1;
            }
            st[0x409] = state->stateIndex; /* remember the daytime state across the sleep cycle */
            state->stateIndex = 0x14;
        }
        else
        {
            return 0;
        }
    }
    switch (state->stateIndex)
    {
    case 0x14:
        if (animCue != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_id_14b);
        }
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED)
        {
            state->stateIndex = 0x15;
            state->stateTimer = (f32)(s32)
            randomGetRange(0, 300);
        }
        break;
    case 0x15:
        if (animCue != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_sa_off);
        }
        state->stateTimer -= timeDelta;
        if (night == 0 && state->stateTimer <= lbl_803E520C)
        {
            state->stateIndex = 0x16;
        }
        {
            f32 t = state->partfxTimer - timeDelta;
            state->partfxTimer = t;
            if (t <= lbl_803E520C)
            {
                if (((GameObject*)obj)->objectFlags & NWMAMMOTH_OBJFLAG_RENDERED)
                {
                    blk.pos[0] = state->spawnPosX;
                    blk.pos[1] = state->spawnPosY;
                    blk.pos[2] = state->spawnPosZ;
                    (*gPartfxInterface)->spawnObject(obj, 0x7f0, &blk, 0x200001, -1, NULL);
                }
                state->partfxTimer = lbl_803E5218;
            }
        }
        break;
    case 0x16:
        if (animCue != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_id_14d);
        }
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED)
        {
            state->stateIndex = st[0x409];
        }
        break;
    }
    return 1;
}

void fn_801CEA14(short* obj, u8* st, u8* mapData)
{
    NwMammothState* state = (NwMammothState*)st;
    switch (fn_801CE078((int*)obj, st))
    {
    case -1:
        state->pathSpeed -= gNwMammothPathAccel * timeDelta;
        if (state->pathSpeed < gNwMammothPathSpeedMin)
        {
            state->pathSpeed = lbl_803E520C;
        }
        break;
    case 0:
        if ((((NwMammothObject*)obj)->hitboxFlags & 4) || state->playerDistanceSq < gNwMammothPlayerNearDistSq)
        {
            state->pathSpeed -= gNwMammothPathDecel * timeDelta;
            if (state->pathSpeed < gNwMammothPathSpeedMin)
            {
                state->pathSpeed = lbl_803E520C;
            }
        }
        else
        {
            state->pathSpeed += gNwMammothPathAccel * timeDelta;
            if (state->pathSpeed > gNwMammothPathSpeedMax)
            {
                state->pathSpeed = *(f32*)&gNwMammothPathSpeedMax;
            }
        }
        break;
    case 1:
        return;
    }
    switch (state->stateIndex)
    {
    case 8:
        {
            Curve* cv = (Curve*)&state->curveState;
            if (Curve_AdvanceAlongPath(cv, state->pathSpeed) != 0 || cv->idx != 0)
            {
                (*gRomCurveInterface)->goNextPoint(cv);
            }
            {
                f32 dx = cv->sample[0] - ((GameObject*)obj)->anim.localPosX;
                f32 dz = cv->sample[2] - ((GameObject*)obj)->anim.localPosZ;
                ObjAnim_SampleRootCurvePhase(oneOverTimeDelta * sqrtf(dx * dx + dz * dz),
                                             (ObjAnimComponent*)obj, &state->animStepScale);
            }
            ((GameObject*)obj)->anim.rotX = (s16)(getAngle(cv->tangent[0], cv->tangent[2]) + 0x8000);
            ((GameObject*)obj)->anim.localPosX = cv->sample[0];
            ((GameObject*)obj)->anim.localPosZ = cv->sample[2];
            if (state->pathSpeed <= lbl_803E520C)
            {
                state->stateIndex = 7;
            }
            break;
        }
    case 7:
        if (state->pathSpeed > lbl_803E5250)
        {
            state->stateIndex = 8;
        }
        break;
    }
    if (((NwMammothMapData*)mapData)->behaviorMode == 1)
    {
        if (GameBit_Get(0x19d) != 0)
        {
            state->triggerList = lbl_803DBF90;
        }
        else if (GameBit_Get(0x1a2) != 0)
        {
            state->triggerList = lbl_803DBF8C;
        }
        else if (GameBit_Get(0x102) != 0)
        {
            state->triggerList = lbl_803DBF88;
        }
        else if (GameBit_Get(0x9e) != 0)
        {
            state->triggerList = lbl_803DBF84;
        }
        else
        {
            state->triggerList = lbl_803DBF80;
        }
    }
    else
    {
        if (GameBit_Get(0x19d) != 0)
        {
            state->triggerList = lbl_803DBFA4;
        }
        else if (GameBit_Get(0x1a2) != 0)
        {
            state->triggerList = lbl_803DBFA0;
        }
        else if (GameBit_Get(0x102) != 0)
        {
            state->triggerList = lbl_803DBF9C;
        }
        else if (GameBit_Get(0x9e) != 0)
        {
            state->triggerList = lbl_803DBF98;
        }
        else
        {
            state->triggerList = lbl_803DBF94;
        }
    }
}

void fn_801CE2BC(int* obj, u8* st, short* objDef)
{
    extern f32 vec3f_distanceSquared(void* a, void* b); /* #57 */
    NwMammothState* state = (NwMammothState*)st;
    int* tw2;
    int* tw;
    int nearestObj = ObjGroup_FindNearestObject(0xf, obj, 0);
    switch (state->stateIndex)
    {
    case 9:
        state->sfxTimer += timeDelta;
        if (state->sfxTimer > gNwMammothSfxInterval)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_skeep_mumb);
            state->sfxTimer -= gNwMammothSfxInterval;
        }
        if (state->playerDistanceSq < (f32)(s32)(objDef[0xc] * objDef[0xc]))
        {
            state->stateIndex = 0xa;
        }
        break;
    case 0xa:
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED)
        {
            state->stateIndex = 0xb;
        }
        break;
    case 0xb:
        state->sfxTimer += timeDelta;
        if (state->sfxTimer > gNwMammothSfxInterval)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_skeep_mumb);
            state->sfxTimer -= gNwMammothSfxInterval;
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(3, (void*)nearestObj, -1);
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
            state->stateIndex = 0xd;
            GameBit_Set(0xce1, 1);
            GameBit_Set(0xd32, 1);
        }
        break;
    case 0xc:
        (*gObjectTriggerInterface)->preempt(nearestObj, 0x5aa);
        (*gObjectTriggerInterface)->runSequence(3, (void*)nearestObj, 0x30);
        state->stateIndex = 0xd;
        break;
    case 0xd:
        {
            int n = 4;
            if (GameBit_Get(0x120) == 0)
            {
                n = 3;
            }
            if (GameBit_Get(0x121) == 0)
            {
                n -= 1;
            }
            {
                int i = 0;
                for (; i < n; i++)
                {
                    if (GameBit_Get(gNwMammothBushGameBits[i]) != 0)
                    {
                        GameBit_Set(gNwMammothBushGameBits[i], 0);
                    }
                    {
                        int* o2 = ObjList_FindObjectById(gNwMammothBushObjectIds[i]);
                        if ((int*)Player_GetTargetObject(*(int*)&state->playerObject) == o2)
                        {
                            fn_8014C66C(o2, (int*)state->playerObject);
                        }
                        else
                        {
                            tw = tumbleweedbush_findNearestActive(&((GameObject*)o2)->anim.worldPosX);
                            if (tw == NULL || vec3f_distanceSquared(&((GameObject*)tw)->anim.worldPosX, &o2[6]) >= gNwMammothTumbleweedDistSqThreshold)
                            {
                                if (vec3f_distanceSquared((char*)&((GameObject*)state->playerObject)->anim.worldPosX, &o2[6]) >=
                                    gNwMammothTumbleweedDistSqThreshold)
                                {
                                    fn_8014C66C(o2, obj);
                                }
                                else
                                {
                                    fn_8014C66C(o2, (int*)state->playerObject);
                                }
                            }
                            else
                            {
                                fn_8014C66C(o2, tw);
                            }
                        }
                    }
                }
            }
            {
                tw2 = tumbleweedbush_findNearestActive(&state->spawnPosX);
                if (tw2 != NULL)
                {
                    int* tk = getTrickyObject();
                    /* Tricky DLL interface +0x28: bark at the bush */
                    (*(void (**)(int*, int*, int, int))((char*)*((GameObject*)tk)->anim.dll + 0x28))(
                        tk, obj, 1, 1);
                }
                state->triggerList = lbl_803DBFA8;
                if (state->trackedObject == NULL)
                {
                    short* cfg = ((GameObject*)obj)->anim.placementData;
                    if (tw2 != NULL && ((GameObject*)tw2)->anim.seqId == 0x3fb)
                    {
                        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)tw2)->anim.worldPosX) < (f32)(s32)(cfg[0xc] * cfg[0xc]))
                        {
                            if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                            {
                                Sfx_PlayFromObject((u32)obj, SFXTRIG_mammoth_snowstep);
                            }
                            /* Tumbleweed bush DLL interface +0x30: is the bush busy? +0x2C: send it rolling to a target position */
                            if ((*(int (**)(int*))((char*)*((GameObject*)tw2)->anim.dll + 0x30))(tw2) == 0)
                            {
                                (*(void (**)(int*, f32*))((char*)*((GameObject*)tw2)->anim.dll + 0x2c))(
                                    tw2, &state->spawnPosX);
                                state->trackedObject = tw2;
                                state->stateIndex = 0xe;
                            }
                        }
                    }
                }
            }
            if (!(state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE))
            {
                (*gGameUIInterface)->initAirMeter(0xc8, 0x5d0);
                state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE);
            }
            break;
        }
    case 0xe:
        if (getXZDistance(&state->spawnPosX, (char*)&((GameObject*)state->trackedObject)->anim.worldPosX) < gNwMammothCaptureDist)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_mammoth_annoyed);
            fn_80163980(*(int*)&state->trackedObject);
            state->stateIndex = 0xf;
        }
        break;
    case 0xf:
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED)
        {
            Obj_FreeObject(*(int*)&state->trackedObject);
            state->trackedObject = NULL;
            if (++state->uiMessageCount > 3)
            {
                state->uiMessageCount = 3;
            }
            GameBit_Set(0x48b, state->uiMessageCount);
            if (state->uiMessageCount >= 3)
            {
                state->stateIndex = 0x11;
            }
            else
            {
                if (state->uiMessageCount % 2 == 0)
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_id_14f);
                }
                state->stateIndex = 0xd;
            }
        }
        break;
    case 0x10:
        (*gObjectTriggerInterface)->preempt(nearestObj, 0x157c);
        (*gObjectTriggerInterface)->runSequence(1, (void*)nearestObj, 2);
        state->stateIndex = 0x13;
        break;
    case 0x11:
        if (!(((GameObject*)state->playerObject)->objectFlags & NWMAMMOTH_OBJFLAG_PARENT_SLACK) && state->airMeterValue >= gNwMammothAirMeterFull)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_menuups16k);
            (*gScreenTransitionInterface)->start(0x14, 1);
            state->stateIndex = 0x12;
            GameBit_Set(0xd32, 0);
            state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_UI_MESSAGE);
            (*gGameUIInterface)->airMeterShutdown();
        }
        break;
    case 0x12:
        if (!(((GameObject*)state->playerObject)->objectFlags & NWMAMMOTH_OBJFLAG_PARENT_SLACK))
        {
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                GameBit_Set(0x102, 1);
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearestObj, -1);
                state->stateIndex = 0x13;
            }
        }
        break;
    case 0x13:
    default:
        if (GameBit_Get(0x224) != 0)
        {
            state->triggerList = lbl_803DBFB0;
        }
        else
        {
            if (GameBit_Get(0xea7) == 0)
            {
                GameBit_Set(0xea7, 1);
                GameBit_Set(0x9d5, 1);
            }
            state->triggerList = lbl_803DBFAC;
        }
        fn_801CE078(obj, st);
        break;
    }
    if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE)
    {
        if (state->airMeterValue < gNwMammothAirMeterPerSegment * state->uiMessageCount)
        {
            state->airMeterValue += timeDelta;
        }
        if (state->airMeterValue >= gNwMammothAirMeterFull)
        {
            (*gGameUIInterface)->runAirMeter(0xc8);
        }
        else
        {
            (*gGameUIInterface)->runAirMeter((int)state->airMeterValue);
        }
    }
}

void nw_mammoth_free(void* obj)
{
    extern void ObjGroup_RemoveObject(void* obj, int group); /* #57 */
    void* node;

    node = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, NW_MAMMOTH_GROUP_ID);
    if ((((NwMammothState*)node)->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE) != 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
}

void nw_mammoth_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    extern void ObjPath_GetPointWorldPosition(void* obj, int idx, void* out0, void* out1, void* out2, int flag); /* #57 */
    extern void objRenderModelAndHitVolumes(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale); /* #57 */
    int i;
    void* node;

    node = ((GameObject*)obj)->extra;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E5210);
    for (i = 0; i < 4; i++)
    {
        ObjPath_GetPointWorldPosition(obj, i,
                                      (char*)node + i * 0xc + 0x45c,
                                      (char*)node + i * 0xc + 0x460,
                                      (char*)node + i * 0xc + 0x464,
                                      0);
    }
    ObjPath_GetPointWorldPosition(obj, 4,
                                  (char*)node + 0xc,
                                  (char*)node + 0x10,
                                  (char*)node + 0x14,
                                  0);
}

enum NwMammothStateFlag
{
    NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
    NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
    NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
    NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
    NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

#pragma inline_max_size(4000)
static inline void nw_mammoth_updateBody(NwMammothObject* obj, int unused)
{
    extern void fn_801CE2BC(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CEA14(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CED2C(int obj, void* state, void* objDef); /* #57 */
    extern void fn_801CEE0C(int obj, void* state, void* objDef); /* #57 */
    extern f32 vec3f_distanceSquared(f32 * obj, f32 * p2); /* #57 */
    extern u8 ObjHitReact_Update(int obj, ObjHitReactEntry * reactionEntryTable, u32 reactionEntryCount,
                                 u32 reactionState, float* reactionStepScale);
    int triggerIndex;
    f32 stepScale;
    int currentMove;
    ObjHitReactEntry* hitReactEntries;
    u8 stateFlags;
    u8 stateIndex;
    NwMammothMapData* mapData;
    NwMammothState* state;
    NwMammothTables* table = (NwMammothTables*)gNwMammothTables;

    (void)unused;
    state = obj->state;
    mapData = obj->mapData;
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_RESET_PATH) != 0)
    {
        state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_RESET_PATH);
    }
    state->playerObject = Obj_GetPlayerObject();
    if (state->playerObject == NULL)
    {
        return;
    }
    stateIndex = state->stateIndex;
    stateFlags = table->stateFlags[stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SOLID) != 0)
    {
        obj->objectFlags = (u16)(obj->objectFlags | NW_MAMMOTH_SOLID_OBJECT_FLAG);
        obj->modelState->flags = obj->modelState->flags & ~(u64)NW_MAMMOTH_MODEL_COLLISION_FLAG;
    }
    else
    {
        obj->objectFlags = (u16)(obj->objectFlags & ~NW_MAMMOTH_SOLID_OBJECT_FLAG);
        obj->modelState->flags = obj->modelState->flags | NW_MAMMOTH_MODEL_COLLISION_FLAG;
    }
    stateFlags = table->stateFlags[state->stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT) == 0)
    {
        if ((stateFlags & NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT) != 0)
        {
            hitReactEntries = &table->heavyHitReactEntry;
        }
        else
        {
            hitReactEntries = &table->normalHitReactEntry;
        }
        state->hitReactState =
            ObjHitReact_Update((int)obj, hitReactEntries, 1, state->hitReactState,
                               &state->hitReactStepScale);
        if (state->hitReactState != 0)
        {
            fn_8003A168((int)obj, state->eyeAnimState);
            characterDoEyeAnims((int)obj, state->eyeAnimState);
            return;
        }
    }
    state->playerDistanceSq = vec3f_distanceSquared(&obj->worldPosX,
                                                    &((NwMammothObject*)state->playerObject)->worldPosX);
    switch (mapData->behaviorMode)
    {
    case 0:
        fn_801CEE0C((int)obj, state, mapData);
        break;
    case 2:
        fn_801CED2C((int)obj, state, mapData);
        break;
    case 1:
    case 3:
        fn_801CEA14((int)obj, state, mapData);
        break;
    case 4:
        fn_801CE2BC((int)obj, state, mapData);
        break;
    }
    if ((table->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_PATH_CONTROL) != 0)
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags | NW_MAMMOTH_PATH_CONTROL_FLAG);
    }
    else
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags & ~NW_MAMMOTH_PATH_CONTROL_FLAG);
        if (((table->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_MENU_ACTION) != 0) &&
            (cMenuGetSelectedItem() != -1))
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        }
        else
        {
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
        }
    }
    stateIndex = state->stateIndex;
    if (obj->currentMove != (currentMove = table->stateMoveIds[stateIndex]))
    {
        stepScale = table->stateMoveStepScales[stateIndex];
        if (stepScale > lbl_803E520C)
        {
            ObjAnim_SetCurrentMove((int)obj, currentMove, lbl_803E520C, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, currentMove, lbl_803E5210, 0);
        }
        state->animStepScale = table->stateMoveStepScales[state->stateIndex];
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, state->animStepScale, timeDelta,
                                                                    &state->animEvents) != 0)
    {
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    else
    {
        state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    objAudioFn_8006ef38((int)obj, &state->animEvents, 8, state->pathPoints, state->pathState,
                        lbl_803E5210, *(f32*)&lbl_803E5210);
    fn_801CDF94((int)obj, state, table->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH);
    state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
    if (((state->runtimeFlags & NW_MAMMOTH_RUNTIME_MENU_LOCK) == 0) && (ObjTrigger_IsSet((int)obj) != 0))
    {
        triggerIndex = randomGetRange(NW_MAMMOTH_TRIGGER_RANDOM_MIN, *state->triggerList);
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
        (*gObjectTriggerInterface)->runSequence(state->triggerList[triggerIndex], obj, -1);
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0)
    {
        (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
        (*gPathControlInterface)->apply(obj, state->pathState);
        (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
    }
}

void nw_mammoth_update(NwMammothObject* obj, int unused)
{
    nw_mammoth_updateBody(obj, unused);
}
#pragma inline_max_size reset

void nw_mammoth_init(NwMammothObject* obj, NwMammothMapData* mapData, int isReload)
{
    u32 pathParam;
    NwMammothState* state;
    int curveParam;

    state = obj->state;
    pathParam = lbl_803E5208;
    obj->rotX = (s16)(mapData->modelIndex << 8);
    obj->seqCallback = nw_mammoth_SeqFn;
    if (isReload != 0)
    {
        return;
    }
    state->animStepScale = gNwMammothDefaultAnimStepScale;
    switch (mapData->behaviorMode)
    {
    case 0:
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        break;
    case 2:
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        if (GameBit_Get(0x19f) != 0)
        {
            state->stateIndex = 6;
        }
        else if (GameBit_Get(0x19d) != 0)
        {
            state->stateIndex = 5;
        }
        else
        {
            state->stateIndex = 4;
        }
        break;
    case 1:
    case 3:
        curveParam = NW_MAMMOTH_CURVE_PARAM;
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
        if ((u8)(*gRomCurveInterface)->initCurve(
            &state->curveState, obj, lbl_803E5254, &curveParam, -1) == 0)
        {
            obj->localPosX = state->curveState.pointX;
            obj->localPosZ = state->curveState.pointZ;
            state->stateIndex = 8;
            state->pathSpeed = gNwMammothPathSpeedMax;
        }
        break;
    case 4:
        state->uiMessageCount = GameBit_Get(0x48b);
        if (GameBit_Get(0x102) != 0)
        {
            state->stateIndex = 0x10;
        }
        else if (GameBit_Get(0xce1) != 0)
        {
            state->stateIndex = 0xc;
            if (state->uiMessageCount >= 3)
            {
                ((NwMammothGameUiInterface*)*gGameUIInterface)->showMessage(NW_MAMMOTH_UI_MESSAGE_ID, NW_MAMMOTH_UI_MESSAGE_TEXT_ID);
                state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE);
                state->stateIndex = 0x11;
            }
        }
        else
        {
            state->stateIndex = 9;
        }
        break;
    }
    if ((state->runtimeFlags & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0)
    {
        u8* path = state->pathState;
        (*gPathControlInterface)->init(path, 3, 2, 1);
        (*gPathControlInterface)->setup(path, NW_MAMMOTH_PATH_SETUP_POINT_COUNT,
                                        gNwMammothPathSetupDataA, gNwMammothPathSetupDataB, &pathParam);
        (*gPathControlInterface)->attachObject(obj, path);
    }
    ObjGroup_AddObject(obj, NW_MAMMOTH_GROUP_ID);
}



u8 gNwMammothPathSetupDataB[] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x25,
    0x00, 0x24, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x29,
    0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x00, 0x00, 0x04, 0x00, 0x05,
    0x00, 0x06, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0xBC, 0x23, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3C, 0x03, 0x12, 0x6F, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0x44, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6,
};

u8 gNwMammothPathSetupDataA[] =
{
    0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00,
    0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00,
    0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00,
    0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00,
};

u8 gNwMammothTables[40] = {
    0x02, 0xDA, 0x03, 0x75, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x3C, 0x44, 0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x02, 0xDA, 0x03, 0x75,
    0x00, 0x31, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6,
    0x00, 0x00, 0x00, 0x00
};
u8 lbl_803268B4[24] = {
    0x04, 0x14, 0x14, 0x04, 0x14, 0x04, 0x04, 0x04, 0x00, 0x29, 0x29, 0x28,
    0x28, 0x28, 0x29, 0x29, 0x29, 0x29, 0x29, 0x04, 0x09, 0x03, 0x09, 0x00
};
int gNwMammothBushObjectIds[4] = { 0x4ABDA, 0x4ABDB, 0x4ABDC, 0x4ABDD };
int gNwMammothBushGameBits[4] = { 0xF22, 0xF23, 0xF24, 0xF25 };

/*__DATA_EXTERNS__*/
extern void sh_tricky_getExtraSize();
extern void sh_tricky_update();
extern void sh_tricky_init();
extern void nw_levcontrol_getExtraSize();
extern void nw_levcontrol_free();
extern void nw_levcontrol_update();
extern void nw_levcontrol_init();
extern void nw_ice_getExtraSize();
extern void nw_ice_free();
extern void nw_ice_render();
extern void nw_ice_update();
extern void nw_ice_init();
extern void nw_animice_getExtraSize();
extern void nw_animice_getObjectTypeId();
extern void nw_animice_free();
extern void nw_animice_render();
extern void nw_animice_hitDetect();
extern void nw_animice_update();
extern void nw_animice_init();
extern void nw_animice_release();
extern void nw_animice_initialise();
extern void nw_tricky_free();
extern void nw_tricky_update();
extern void nw_tricky_init();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gNW_mammothObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_mammoth_init, nw_mammoth_update, (void*)0x00000000, nw_mammoth_render, nw_mammoth_free, (void*)0x00000000, nw_mammoth_getExtraSize };
void* jumptable_80326924[11] = { (void*)((u8*)fn_801CE2BC + 0x5C), (void*)((u8*)fn_801CE2BC + 0xD4), (void*)((u8*)fn_801CE2BC + 0xF0), (void*)((u8*)fn_801CE2BC + 0x190), (void*)((u8*)fn_801CE2BC + 0x1D4), (void*)((u8*)fn_801CE2BC + 0x434), (void*)((u8*)fn_801CE2BC + 0x470), (void*)((u8*)fn_801CE2BC + 0x50C), (void*)((u8*)fn_801CE2BC + 0x550), (void*)((u8*)fn_801CE2BC + 0x5DC), (void*)((u8*)fn_801CE2BC + 0x644) };
void* gNW_trickyObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_tricky_init, nw_tricky_update, (void*)0x00000000, (void*)0x00000000, nw_tricky_free, (void*)0x00000000, nw_tricky_getExtraSize };
void* gNW_animiceObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, nw_animice_initialise, nw_animice_release, (void*)0x00000000, nw_animice_init, nw_animice_update, nw_animice_hitDetect, nw_animice_render, nw_animice_free, nw_animice_getObjectTypeId, nw_animice_getExtraSize };
void* gNW_iceObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_ice_init, nw_ice_update, (void*)0x00000000, nw_ice_render, nw_ice_free, (void*)0x00000000, nw_ice_getExtraSize };
u8 lbl_803269F8[308] = { 0, 4, 71, 213, 0, 4, 71, 214, 0, 4, 71, 213, 0, 4, 71, 214, 0, 4, 71, 213, 0, 4, 71, 214, 0, 4, 71, 213, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 11, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 180, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 182, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 181, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183, 0, 183 };
void* gNW_levcontrolObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_levcontrol_init, nw_levcontrol_update, (void*)0x00000000, (void*)0x00000000, nw_levcontrol_free, (void*)0x00000000, nw_levcontrol_getExtraSize };
void* jumptable_80326B64[13] = { (void*)((u8*)nw_levcontrol_update + 0x330), (void*)((u8*)nw_levcontrol_update + 0x378), (void*)((u8*)nw_levcontrol_update + 0x3CC), (void*)((u8*)nw_levcontrol_update + 0x3F4), (void*)((u8*)nw_levcontrol_update + 0x3F4), (void*)((u8*)nw_levcontrol_update + 0x3F4), (void*)((u8*)nw_levcontrol_update + 0x3F4), (void*)((u8*)nw_levcontrol_update + 0x3F4), (void*)((u8*)nw_levcontrol_update + 0x400), (void*)((u8*)nw_levcontrol_update + 0x420), (void*)((u8*)nw_levcontrol_update + 0x43C), (void*)((u8*)nw_levcontrol_update + 0x544), (void*)((u8*)nw_levcontrol_update + 0x564) };
void* gSH_trickyObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, sh_tricky_init, sh_tricky_update, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, sh_tricky_getExtraSize };
