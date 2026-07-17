#include "main/dll/partfx_interface.h"
#include "main/object_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebit_ids.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_path.h"
#include "main/objprint_character_api.h"
#include "main/object.h"
#include "main/obj_trigger.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/screen_transition.h"
#include "main/dll/NW/dll_01A1_nwmammoth.h"
#include "main/dll/NW/dll_01A2_nwtricky.h"
#include "main/dll/NW/dll_01A3_nwanimice.h"
#include "main/dll/NW/dll_01A4_nwice.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/audio/sfx.h"
#include "main/vecmath.h"
#include "main/curve.h"
#include "main/sky_interface.h"
#include "main/dll/player_target.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render.h"
#include "main/dll/path_control_interface.h"

u8 lbl_803DBF70[4] = {1, 0, 0, 0};
u8 lbl_803DBF74[4] = {1, 1, 0, 0};
u8 lbl_803DBF78[4] = {1, 3, 0, 0};
u8 lbl_803DBF7C[4] = {1, 5, 0, 0};
u8 lbl_803DBF80[4] = {2, 0, 1, 0};
u8 lbl_803DBF84[4] = {2, 3, 4, 0};
u8 lbl_803DBF88[4] = {3, 2, 3, 4};
u8 lbl_803DBF8C[4] = {2, 5, 6, 0};
u8 lbl_803DBF90[4] = {1, 7, 0, 0};
u8 lbl_803DBF94[4] = {2, 8, 9, 0};
u8 lbl_803DBF98[4] = {3, 0x0A, 0x0B, 0x0C};
u8 lbl_803DBF9C[4] = {2, 0x0B, 0x0C, 0};
u8 lbl_803DBFA0[4] = {2, 0x0D, 0x0E, 0};
u8 lbl_803DBFA4[4] = {1, 0x0F, 0, 0};
u8 lbl_803DBFA8[4] = {2, 0, 1, 0};
u8 lbl_803DBFAC[4] = {2, 2, 3, 0};
u8 lbl_803DBFB0[4] = {1, 4, 0, 0};
u8 lbl_803DBFB4[4] = {1, 0, 0, 0};
u8 lbl_803DBFB8[4] = {1, 1, 0, 0};
u8 lbl_803DBFBC[4] = {1, 2, 0, 0};

#define ObjGroup_FindNearestObjectLegacy(group, obj, distance) \
    ((u32 (*)())ObjGroup_FindNearestObject)((group), (obj), (distance))
#define ObjTrigger_IsSetLegacy(obj) \
    ((int (*)())ObjTrigger_IsSet)((obj))
#define NWMAMMOTH_PARTFX               0x7f0
#define NWMAMMOTH_OBJFLAG_PARENT_SLACK 0x1000
#define NWMAMMOTH_OBJFLAG_RENDERED     0x800
/* object group scanned for the nearest target (player group) */
#define NWMAMMOTH_TARGET_OBJGROUP    0xf
#define NWMAMMOTH_AIRMETER_BGTEXTURE 0x5d0 /* air-meter background texture id */
enum NwMammothRuntimeFlag
{
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};
extern u32 objAudioFn_8006ef38();

extern f32 lbl_803E520C;
extern f32 lbl_803E5218;
extern f32 gNwMammothPathAccel;
extern f32 gNwMammothPathSpeedMin;
extern f32 gNwMammothPlayerNearDistSq;
extern f32 gNwMammothPathDecel;
extern f32 gNwMammothPathSpeedMax;
extern f32 lbl_803E5250;
extern u8 lbl_803DBF70[4];
extern u8 lbl_803DBF74[4];
extern u8 lbl_803DBF78[4];
extern u8 lbl_803DBF7C[4];
extern u8 lbl_803DBF80[4];
extern u8 lbl_803DBFB4[4];
extern u8 lbl_803DBFB8[4];
extern u8 lbl_803DBFBC[4];
extern u8 lbl_803DBF84[4];
extern u8 lbl_803DBF88[4];
extern u8 lbl_803DBF8C[4];
extern u8 lbl_803DBF90[4];
extern u8 lbl_803DBF94[4];
extern u8 lbl_803DBF98[4];
extern u8 lbl_803DBF9C[4];
extern u8 lbl_803DBFA0[4];
extern u8 lbl_803DBFA4[4];
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
extern GameObject* tumbleweedbush_findNearestActive(void* pos);
extern void fn_80163980(int o);
extern f32 lbl_803E5210;
extern void fn_8003A168(GameObject* obj, void* p);
extern void fn_801CDF94(GameObject* obj, void* state, int flag);
extern u8 gNwMammothTables[];
extern u8 gNwMammothPathSetupDataA[];
extern u8 gNwMammothPathSetupDataB[];
extern u32 lbl_803E5208;
extern f32 lbl_803E5254;
extern f32 gNwMammothDefaultAnimStepScale;

int fn_801CE078(int* obj, u8* state);

int NW_mammoth_getExtraSize(void)
{
    return 0x48c;
}

#pragma dont_inline on
void fn_801CEE0C(int obj, int baddie, NwMammothMapData* mapData)
{
    NwMammothState* state = (NwMammothState*)baddie;

    (void)mapData;
    if (fn_801CE078((int*)obj, (u8*)baddie) != 0)
        return;

    switch (state->stateIndex)
    {
    case 0:
        state->triggerList = lbl_803DBF70;
        if (mainGetBit(211) != 0)
        {
            state->stateIndex = 1;
        }
        break;
    case 1:
        state->triggerList = lbl_803DBF74;
        switch (mainGetBit(GAMEBIT_ITEM_AlpineRoot_Used))
        {
        case 0:
            if (ObjTrigger_IsSetById(obj, 1398) != 0)
            {
                mainSetBits(GAMEBIT_ITEM_AlpineRoot_Used, 1);
                gameBitDecrement(GAMEBIT_ITEM_IMAlpineRoot_Count);
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
            mainSetBits(GAMEBIT_ITEM_AlpineRoot_Used, 2);
            gameBitDecrement(GAMEBIT_ITEM_IMAlpineRoot_Count);
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

void fn_801CED2C(int obj, int baddie, NwMammothMapData* mapData)
{
    NwMammothState* state = (NwMammothState*)baddie;

    (void)mapData;
    switch (state->stateIndex)
    {
    case 4:
        state->triggerList = lbl_803DBFB4;
        if (ObjTrigger_IsSetById(obj, 418) != 0)
        {
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
            mainSetBits(GAMEBIT_SnowHornArtifact19D, 1);
            mainSetBits(GAMEBIT_ITEM_NWSnowHornArtifact_Used, 1);
            mainSetBits(GAMEBIT_ITEM_SnowHornArtifactEE5, 1);
            mainSetBits(GAMEBIT_ITEM_SnowHornArtifactEE6, 1);
            state->stateIndex = 5;
        }
        break;
    case 5:
        state->triggerList = lbl_803DBFB8;
        if (mainGetBit(GAMEBIT_SnowHornArtifact19F) != 0)
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
            state->stateTimer = (f32)(s32)randomGetRange(0, 300);
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
                    (*gPartfxInterface)->spawnObject(obj, NWMAMMOTH_PARTFX, &blk, 0x200001, -1, NULL);
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
            ObjAnim_SampleRootCurvePhase(oneOverTimeDelta * sqrtf(dx * dx + dz * dz), (ObjAnimComponent*)obj,
                                         &state->animStepScale);
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
        if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0)
        {
            state->triggerList = lbl_803DBF90;
        }
        else if (mainGetBit(GAMEBIT_ITEM_NWSnowHornArtifact_Got) != 0)
        {
            state->triggerList = lbl_803DBF8C;
        }
        else if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0)
        {
            state->triggerList = lbl_803DBF88;
        }
        else if (mainGetBit(0x9e) != 0)
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
        if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0)
        {
            state->triggerList = lbl_803DBFA4;
        }
        else if (mainGetBit(GAMEBIT_ITEM_NWSnowHornArtifact_Got) != 0)
        {
            state->triggerList = lbl_803DBFA0;
        }
        else if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0)
        {
            state->triggerList = lbl_803DBF9C;
        }
        else if (mainGetBit(0x9e) != 0)
        {
            state->triggerList = lbl_803DBF98;
        }
        else
        {
            state->triggerList = lbl_803DBF94;
        }
    }
}

void NW_mammoth_free(GameObject* obj);
void NW_mammoth_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);

u8 gNwMammothTables[40] = {0x02, 0xDA, 0x03, 0x75, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x44,
                           0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00, 0x02, 0xDA, 0x03, 0x75, 0x00, 0x31, 0xFF, 0xFF,
                           0x00, 0x00, 0x00, 0x00, 0x3C, 0x44, 0x9B, 0xA6, 0x00, 0x00, 0x00, 0x00};

u8 gNwMammothPathSetupDataA[] = {
    0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xC1, 0xA0, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0xA0, 0x00, 0x00, 0xC1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xA0, 0x00, 0x00,
};

u8 gNwMammothPathSetupDataB[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x25,
    0x00, 0x24, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23, 0x00, 0x29, 0x00, 0x23, 0x00, 0x23, 0x00, 0x23,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3,
    0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0xBC, 0x23, 0xD7, 0x0A,
    0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3C, 0x03,
    0x12, 0x6F, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A, 0x3B, 0xA3, 0xD7, 0x0A,
    0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0x44, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6,
};

u8 lbl_803268B4[24] = {0x04, 0x14, 0x14, 0x04, 0x14, 0x04, 0x04, 0x04, 0x00, 0x29, 0x29, 0x28,
                       0x28, 0x28, 0x29, 0x29, 0x29, 0x29, 0x29, 0x04, 0x09, 0x03, 0x09, 0x00};
int gNwMammothBushObjectIds[4] = {0x4ABDA, 0x4ABDB, 0x4ABDC, 0x4ABDD};
int gNwMammothBushGameBits[4] = {0xF22, 0xF23, 0xF24, 0xF25};

void* gNW_mammothObjDescriptor[14] = {(void*)0x00000000, (void*)0x00000000,      (void*)0x00000000, (void*)0x00090000,
                                      (void*)0x00000000, (void*)0x00000000,      (void*)0x00000000, NW_mammoth_init,
                                      NW_mammoth_update, (void*)0x00000000,      NW_mammoth_render, NW_mammoth_free,
                                      (void*)0x00000000, NW_mammoth_getExtraSize};

void fn_801CE2BC(int* obj, u8* st, short* objDef)
{
    NwMammothState* state = (NwMammothState*)st;
    GameObject* tw2;
    GameObject* tw;
    int nearestObj = ObjGroup_FindNearestObjectLegacy(NWMAMMOTH_TARGET_OBJGROUP, obj, 0);
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
        if (ObjTrigger_IsSetLegacy(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(3, (void*)nearestObj, -1);
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_MENU_LOCK);
            state->stateIndex = 0xd;
            mainSetBits(GAMEBIT_NW_ReturnedTo, 1);
            mainSetBits(0xd32, 1);
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
        if (mainGetBit(0x120) == 0)
        {
            n = 3;
        }
        if (mainGetBit(0x121) == 0)
        {
            n -= 1;
        }
        {
            int i = 0;
            for (; i < n; i++)
            {
                if (mainGetBit(gNwMammothBushGameBits[i]) != 0)
                {
                    mainSetBits(gNwMammothBushGameBits[i], 0);
                }
                {
                    int* o2 = (int*)ObjList_FindObjectById(gNwMammothBushObjectIds[i]);
                    if ((int*)fn_80296118((GameObject*)*(int*)&state->playerObject) == o2)
                    {
                        fn_8014C66C((GameObject*)o2, state->playerObject);
                    }
                    else
                    {
                        tw = tumbleweedbush_findNearestActive(&((GameObject*)o2)->anim.worldPosX);
                        if (tw == NULL || vec3f_distanceSquared(&tw->anim.worldPosX, (f32*)&o2[6]) >=
                                              gNwMammothTumbleweedDistSqThreshold)
                        {
                            if (vec3f_distanceSquared(&((GameObject*)state->playerObject)->anim.worldPosX,
                                                      (f32*)&o2[6]) >= gNwMammothTumbleweedDistSqThreshold)
                            {
                                fn_8014C66C((GameObject*)o2, (GameObject*)obj);
                            }
                            else
                            {
                                fn_8014C66C((GameObject*)o2, state->playerObject);
                            }
                        }
                        else
                        {
                            fn_8014C66C((GameObject*)o2, (GameObject*)tw);
                        }
                    }
                }
            }
        }
        {
            tw2 = tumbleweedbush_findNearestActive(&state->spawnPosX);
            if (tw2 != NULL)
            {
                int* tk = (int*)getTrickyObject();
                /* Tricky DLL interface +0x28: bark at the bush */
                (*(void (**)(int*, int*, int, int))((char*)*((GameObject*)tk)->anim.dll + 0x28))(tk, obj, 1, 1);
            }
            state->triggerList = lbl_803DBFA8;
            if (state->trackedObject == NULL)
            {
                short* cfg = ((GameObject*)obj)->anim.placementData;
                if (tw2 != NULL && tw2->anim.seqId == 0x3fb)
                {
                    if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, &tw2->anim.worldPosX) <
                        (f32)(s32)(cfg[0xc] * cfg[0xc]))
                    {
                        if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
                        {
                            Sfx_PlayFromObject((u32)obj, SFXTRIG_mammoth_snowstep);
                        }
                        /* Tumbleweed bush DLL interface +0x30: is the bush busy? +0x2C: send it rolling to a target position */
                        if ((*(int (**)(int*))((char*)*tw2->anim.dll + 0x30))((int*)tw2) == 0)
                        {
                            (*(void (**)(int*, f32*))((char*)*tw2->anim.dll + 0x2c))((int*)tw2,
                                                                                                    &state->spawnPosX);
                            state->trackedObject = tw2;
                            state->stateIndex = 0xe;
                        }
                    }
                }
            }
        }
        if (!(state->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE))
        {
            (*gGameUIInterface)->initAirMeter(0xc8, NWMAMMOTH_AIRMETER_BGTEXTURE);
            state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_UI_MESSAGE);
        }
        break;
    }
    case 0xe:
        if (getXZDistance(&state->spawnPosX, &state->trackedObject->anim.worldPosX) <
            gNwMammothCaptureDist)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_mammoth_annoyed);
            fn_80163980((int)state->trackedObject);
            state->stateIndex = 0xf;
        }
        break;
    case 0xf:
        if (state->runtimeFlags & NW_MAMMOTH_RUNTIME_ANIM_ENDED)
        {
            Obj_FreeObject(state->trackedObject);
            state->trackedObject = NULL;
            if (++state->uiMessageCount > 3)
            {
                state->uiMessageCount = 3;
            }
            mainSetBits(GAMEBIT_NW_MammothTumbleweedCount, state->uiMessageCount);
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
        if (!(((GameObject*)state->playerObject)->objectFlags & NWMAMMOTH_OBJFLAG_PARENT_SLACK) &&
            state->airMeterValue >= gNwMammothAirMeterFull)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_menuups16k);
            (*gScreenTransitionInterface)->start(0x14, 1);
            state->stateIndex = 0x12;
            mainSetBits(0xd32, 0);
            state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_UI_MESSAGE);
            (*gGameUIInterface)->airMeterShutdown();
        }
        break;
    case 0x12:
        if (!(((GameObject*)state->playerObject)->objectFlags & NWMAMMOTH_OBJFLAG_PARENT_SLACK))
        {
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                mainSetBits(GAMEBIT_NW_RescuedSnowHornGateKeeper, 1);
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearestObj, -1);
                state->stateIndex = 0x13;
            }
        }
        break;
    case 0x13:
    default:
        if (mainGetBit(0x224) != 0)
        {
            state->triggerList = lbl_803DBFB0;
        }
        else
        {
            if (mainGetBit(0xea7) == 0)
            {
                mainSetBits(0xea7, 1);
                mainSetBits(GAMEBIT_IncomingCommunication, 1);
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
#pragma dont_inline reset

void NW_mammoth_free(GameObject* obj)
{
    void* node;

    node = (obj)->extra;
    ObjGroup_RemoveObject((int)obj, NW_MAMMOTH_GROUP_ID);
    if ((((NwMammothState*)node)->runtimeFlags & NW_MAMMOTH_RUNTIME_UI_MESSAGE) != 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
}

void NW_mammoth_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int i;
    void* node;

    node = (obj)->extra;
    objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E5210);
    for (i = 0; i < 4; i++)
    {
        ObjPath_GetPointWorldPosition(obj, i, (f32*)((char*)node + i * 0xc + 0x45c),
                                      (f32*)((char*)node + i * 0xc + 0x460),
                                      (f32*)((char*)node + i * 0xc + 0x464), 0);
    }
    ObjPath_GetPointWorldPosition(obj, 4, (f32*)((char*)node + 0xc), (f32*)((char*)node + 0x10),
                                  (f32*)((char*)node + 0x14), 0);
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

typedef u8 (*NwMammothHitReactUpdateFn)(int obj, ObjHitReactEntry* reactionEntryTable, u32 reactionEntryCount,
                                        u32 reactionState, float* reactionStepScale);

#pragma inline_max_size(4000)
static inline void nw_mammoth_updateBody(NwMammothObject* obj, int unused)
{
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
        state->hitReactState = ((NwMammothHitReactUpdateFn)ObjHitReact_Update)(
            (int)obj, hitReactEntries, 1, state->hitReactState, &state->hitReactStepScale);
        if (state->hitReactState != 0)
        {
            fn_8003A168((GameObject*)obj, state->eyeAnimState);
            characterDoEyeAnimsState((GameObject*)obj, state->eyeAnimState);
            return;
        }
    }
    state->playerDistanceSq =
        vec3f_distanceSquared(&obj->worldPosX, &((NwMammothObject*)state->playerObject)->worldPosX);
    switch (mapData->behaviorMode)
    {
    case 0:
        fn_801CEE0C((int)obj, (int)state, mapData);
        break;
    case 2:
        fn_801CED2C((int)obj, (int)state, mapData);
        break;
    case 1:
    case 3:
        fn_801CEA14((short*)obj, (u8*)state, (u8*)mapData);
        break;
    case 4:
        fn_801CE2BC((int*)obj, (u8*)state, (short*)mapData);
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
            (cMenuGetSelectedItemInt() != -1))
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
    if (ObjAnim_AdvanceCurrentMove((int)obj, state->animStepScale, timeDelta,
                                                                    &state->animEvents) != 0)
    {
        state->runtimeFlags = (u8)(state->runtimeFlags | NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    else
    {
        state->runtimeFlags = (u8)(state->runtimeFlags & ~NW_MAMMOTH_RUNTIME_ANIM_ENDED);
    }
    objAudioFn_8006ef38((int)obj, &state->animEvents, 8, state->pathPoints, state->pathState, lbl_803E5210,
                        *(f32*)&lbl_803E5210);
    fn_801CDF94((GameObject*)obj, state, table->stateFlags[state->stateIndex] & NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH);
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

void NW_mammoth_update(NwMammothObject* obj, int unused)
{
    nw_mammoth_updateBody(obj, unused);
}
#pragma inline_max_size reset

void NW_mammoth_init(NwMammothObject* obj, NwMammothMapData* mapData, int isReload)
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
        if (mainGetBit(GAMEBIT_SnowHornArtifact19F) != 0)
        {
            state->stateIndex = 6;
        }
        else if (mainGetBit(GAMEBIT_SnowHornArtifact19D) != 0)
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
        if ((u8)(*gRomCurveInterface)->initCurve(&state->curveState, obj, lbl_803E5254, &curveParam, -1) == 0)
        {
            obj->localPosX = state->curveState.pointX;
            obj->localPosZ = state->curveState.pointZ;
            state->stateIndex = 8;
            state->pathSpeed = gNwMammothPathSpeedMax;
        }
        break;
    case 4:
        state->uiMessageCount = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        if (mainGetBit(GAMEBIT_NW_RescuedSnowHornGateKeeper) != 0)
        {
            state->stateIndex = 0x10;
        }
        else if (mainGetBit(GAMEBIT_NW_ReturnedTo) != 0)
        {
            state->stateIndex = 0xc;
            if (state->uiMessageCount >= 3)
            {
                ((NwMammothGameUiInterface*)*gGameUIInterface)
                    ->showMessage(NW_MAMMOTH_UI_MESSAGE_ID, NW_MAMMOTH_UI_MESSAGE_TEXT_ID);
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
        (*gPathControlInterface)
            ->setup(path, NW_MAMMOTH_PATH_SETUP_POINT_COUNT, gNwMammothPathSetupDataA, gNwMammothPathSetupDataB,
                    &pathParam);
        (*gPathControlInterface)->attachObject(obj, path);
    }
    ObjGroup_AddObject((int)obj, NW_MAMMOTH_GROUP_ID);
}

void* gNW_trickyObjDescriptor[14] = {(void*)0x00000000, (void*)0x00000000,     (void*)0x00000000, (void*)0x00090000,
                                     (void*)0x00000000, (void*)0x00000000,     (void*)0x00000000, NW_tricky_init,
                                     NW_tricky_update,  (void*)0x00000000,     (void*)0x00000000, NW_tricky_free,
                                     (void*)0x00000000, NW_tricky_getExtraSize};
void* gNW_animiceObjDescriptor[14] = {(void*)0x00000000,          (void*)0x00000000,      (void*)0x00000000,
                                      (void*)0x00090000,          nw_animice_initialise,  nw_animice_release,
                                      (void*)0x00000000,          nw_animice_init,        nw_animice_update,
                                      nw_animice_hitDetect,       nw_animice_render,      nw_animice_free,
                                      nw_animice_getObjectTypeId, nw_animice_getExtraSize};
void* gNW_iceObjDescriptor[14] = {(void*)0x00000000, (void*)0x00000000,  (void*)0x00000000, (void*)0x00090000,
                                  (void*)0x00000000, (void*)0x00000000,  (void*)0x00000000, NW_ice_init,
                                  NW_ice_update,     (void*)0x00000000,  NW_ice_render,     NW_ice_free,
                                  (void*)0x00000000, NW_ice_getExtraSize};
u8 lbl_803269F8[308] = {
    0,  4,   71, 213, 0, 4,   71, 214, 0, 4,   71, 213, 0, 4,   71, 214, 0, 4,   71, 213, 0, 4,   71, 214, 0, 4,
    71, 213, 0,  0,   0, 2,   0,  0,   0, 3,   0,  0,   0, 4,   0,  0,   0, 5,   0,  0,   0, 6,   0,  0,   0, 7,
    0,  0,   0,  1,   0, 0,   0,  3,   0, 0,   0,  4,   0, 0,   0,  5,   0, 0,   0,  6,   0, 0,   0,  7,   0, 0,
    0,  8,   0,  0,   0, 11,  0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180,
    0,  180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  180, 0, 180,
    0,  180, 0,  180, 0, 180, 0,  180, 0, 180, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182,
    0,  182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182,
    0,  182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  182, 0, 182, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181,
    0,  181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181,
    0,  181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  181, 0, 181, 0,  183, 0, 183, 0,  183, 0, 183,
    0,  183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183,
    0,  183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183, 0,  183, 0, 183};
