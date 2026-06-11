#include "main/dll/creator1D4.h"
#include "main/game_object.h"
#include "main/dll/dim2conveyor.h"
#include "main/dll/ped.h"
#include "main/gameplay_runtime.h"
#include "main/objHitReact.h"
#include "main/objanim.h"

extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAudioFn_8006ef38();

extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void fn_8003A168(int obj, void* p);
extern void characterDoEyeAnims(int obj, void* p);
extern int cMenuGetSelectedItem(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void fn_801CDF94(int obj, void* state, int flag);
extern void fn_801CEE0C(int obj, void* state, void* objDef);
extern void fn_801CED2C(int obj, void* state, void* objDef);
extern void fn_801CEA14(int obj, void* state, void* objDef);
extern void fn_801CE2BC(int obj, void* state, void* objDef);
extern void Sfx_StopObjectChannel(void* obj, int channel);

extern u8 lbl_803267C0[];
extern u8 lbl_803267E8[];
extern u8 lbl_80326818[];
extern ObjHitReactEntry DAT_80327400;
extern ObjHitReactEntry DAT_80327414;
extern undefined4 DAT_80327468;
extern undefined4 DAT_80327498;
extern undefined4 DAT_803274f4;
extern NwMammothGameUiInterface** gGameUIInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern NwMammothPathControlInterface** gPathControlInterface;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern u32 lbl_803E5208;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;
extern f32 lbl_803E524C;
extern f32 lbl_803E5254;
extern f32 lbl_803E5258;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;

#define gNwMammothNormalHitReactEntry DAT_80327400
#define gNwMammothHeavyHitReactEntry DAT_80327414
#define gNwMammothStateMoveIds DAT_80327468
#define gNwMammothStateMoveStepScales DAT_80327498
#define gNwMammothStateFlags DAT_803274f4

#define NW_MAMMOTH_STATE_FLAGS(table) ((u8 *)((table) + 0xf4))
#define NW_MAMMOTH_MOVE_IDS(table) ((s16 *)((table) + 0x68))
#define NW_MAMMOTH_MOVE_STEP_SCALES(table) ((f32 *)((table) + 0x98))
#define NW_MAMMOTH_HIT_REACT_ENTRIES(table) ((ObjHitReactEntry *)(table))
#define NW_MAMMOTH_HEAVY_HIT_REACT_ENTRIES(table) \
  ((ObjHitReactEntry *)((table) + sizeof(ObjHitReactEntry)))
#define NW_MAMMOTH_HIT_REACT_STEP_SCALE(state) ((f32 *)((state) + 0x50))
#define NW_MAMMOTH_HIT_REACT_STATE(state) ((state)[0x3d4])

enum NwMammothStateFlag
{
    NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
    NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
    NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
    NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
    NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

enum NwMammothRuntimeFlag
{
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};

/*
 * --INFO--
 *
 * Function: nw_mammoth_update
 * EN v1.0 Address: 0x801CF0AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF2E0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_mammoth_update(NwMammothObject* obj, int param_2)
{
    NwMammothTables* table = (NwMammothTables*)lbl_803267C0;
    NwMammothState* state;
    NwMammothMapData* mapData;
    u8 stateIndex;
    u8 stateFlags;
    ObjHitReactEntry* hitReactEntries;
    int currentMove;
    f32 stepScale;
    int triggerIndex;

    (void)param_2;
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
    stateFlags = table->stateFlags[state->stateIndex];
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_PATH_CONTROL) != 0)
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags | NW_MAMMOTH_PATH_CONTROL_FLAG);
    }
    else
    {
        obj->hitboxFlags = (u8)(obj->hitboxFlags & ~NW_MAMMOTH_PATH_CONTROL_FLAG);
        if (((stateFlags & NW_MAMMOTH_STATE_FLAG_MENU_ACTION) != 0) &&
            (cMenuGetSelectedItem() != -1))
        {
            fn_8002B6D8((int)obj, 0, 0, 0, 0, 4);
        }
        else
        {
            fn_8002B6D8((int)obj, 0, 0, 0, 0, 2);
        }
    }
    stateIndex = state->stateIndex;
    currentMove = table->stateMoveIds[stateIndex];
    if (obj->currentMove != currentMove)
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
    fn_801CDF94((int)obj, state, table->stateFlags[state->stateIndex] & 4);
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


/*
 * --INFO--
 *
 * Function: nw_mammoth_init
 * EN v1.0 Address: 0x801CF4F0
 * EN v1.0 Size: 668b
 */
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
    state->animStepScale = lbl_803E5258;
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
            state->pathSpeed = lbl_803E524C;
        }
        break;
    case 4:
        state->uiMessageCount = (s8)GameBit_Get(0x48b);
        if (GameBit_Get(0x102) != 0)
        {
            state->stateIndex = 0x10;
        }
        else if (GameBit_Get(0xce1) != 0)
        {
            state->stateIndex = 0xc;
            if (state->uiMessageCount >= 3)
            {
                (*gGameUIInterface)->showMessage(NW_MAMMOTH_UI_MESSAGE_ID, NW_MAMMOTH_UI_MESSAGE_TEXT_ID);
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
                                        lbl_803267E8, lbl_80326818, &pathParam);
        (*gPathControlInterface)->attachObject(obj, path);
    }
    ObjGroup_AddObject(obj, NW_MAMMOTH_GROUP_ID);
}


/*
 * --INFO--
 *
 * Function: FUN_801cf0b4
 * EN v1.0 Address: 0x801CF0B4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CF570
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: nw_tricky_getExtraSize
 * EN v1.0 Address: 0x801CF7B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int nw_tricky_getExtraSize(void)
{
    return 8;
}

/*
 * --INFO--
 *
 * Function: nw_tricky_SeqFn
 * EN v1.0 Address: 0x801CF78C
 * EN v1.0 Size: 44b
 */
int nw_tricky_SeqFn(void)
{
    Sfx_StopObjectChannel(getTrickyObject(), 16);
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf108
 * EN v1.0 Address: 0x801CF108
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801CF5C4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
void nw_tricky_free(int obj)
{
    (void)obj;
    GameBit_Set(0x4e4, 1);
}
