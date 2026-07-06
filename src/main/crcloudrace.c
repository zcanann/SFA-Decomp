#include "main/crcloudrace.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"

void crcloudrace_updateRaceState(int obj);

extern f32 lbl_803E6748;
extern u32 fn_802972A8(int obj);
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;

typedef void (*CrCloudRaceRenderScaleFn)(double scale);

int crcloudrace_getExtraSize(void)
{
  return sizeof(CrCloudRaceState);
}

int crcloudrace_getObjectTypeId(void)
{
  return 0;
}

void crcloudrace_free(void)
{
  return;
}

void crcloudrace_render(u32 obj,u32 p2,u32 p3,
                        u32 p4,u32 p5,char visible)
{
  int draw;

  draw = visible;
  if (draw != 0) {
    ((CrCloudRaceRenderScaleFn)objRenderModelAndHitVolumes)((double)lbl_803E6748);
  }
  return;
}

void crcloudrace_hitDetect(void)
{
  return;
}

void crcloudrace_update(CrCloudRaceObject *obj)
{
  u32 eventActive;
  CrCloudRaceState *state;

  state = obj->state;
  if (obj->unkF8 == 0) {
    eventActive = GameBit_Get(CRCLOUDRACE_GAMEBIT_EFFECT_CLEAR);
    if (eventActive != 0) {
      getEnvfxActImmediately(obj,obj,CRCLOUDRACE_ENVFX_CLEAR_A,0);
      getEnvfxActImmediately(obj,obj,CRCLOUDRACE_ENVFX_CLEAR_B,0);
      GameBit_Set(CRCLOUDRACE_GAMEBIT_EFFECT_CLEAR,0);
      unlockLevel(0,0,1);
    }
    obj->unkF4 = 1;
  }
  crcloudrace_updateRaceState((int)obj);
  state->flags &= ~1;
  SCGameBitLatch_Update((SCGameBitLatchState *)state->effect,1,-1,-1,
                        CRCLOUDRACE_GAMEBIT_START_LATCH_A,CRCLOUDRACE_GAMEBIT_START_LATCH_B);
  SCGameBitLatch_Update((SCGameBitLatchState *)state->effect,2,-1,-1,
                        CRCLOUDRACE_GAMEBIT_START_LATCH_A,CRCLOUDRACE_GAMEBIT_START_LATCH_C);
  return;
}

void crcloudrace_init(CrCloudRaceObject *obj)
{
  CrCloudRaceState *state;

  state = obj->state;
  obj->animEventCallback = crcloudrace_completionCallback;
  state->phase = CRCLOUDRACE_PHASE_START;
  storeZeroToFloatParam(state->timer);
  GameBit_Set(CRCLOUDRACE_GAMEBIT_START_LATCH_A,1);
  streamFn_8000a380(3,2,1000);
  return;
}


void crcloudrace_release(void)
{
  return;
}

void crcloudrace_initialise(void)
{
  return;
}

ObjectDescriptor gCrCloudRaceObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)crcloudrace_initialise,
    (ObjectDescriptorCallback)crcloudrace_release,
    0,
    (ObjectDescriptorCallback)crcloudrace_init,
    (ObjectDescriptorCallback)crcloudrace_update,
    (ObjectDescriptorCallback)crcloudrace_hitDetect,
    (ObjectDescriptorCallback)crcloudrace_render,
    (ObjectDescriptorCallback)crcloudrace_free,
    (ObjectDescriptorCallback)crcloudrace_getObjectTypeId,
    crcloudrace_getExtraSize,
};

int crcloudrace_completionCallback(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    CrCloudRaceState *state = ((CrCloudRaceObject *)obj)->state;
    int i;

    state->flags |= CRCLOUDRACE_STATE_FLAG_COMPLETION_CALLBACK;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case CRCLOUDRACE_COMPLETION_ANIM_EVENT:
            GameBit_Set(CRCLOUDRACE_GAMEBIT_COMPLETION_EVENT, 1);
            GameBit_Set(CRCLOUDRACE_GAMEBIT_DRAG_ROCK_CLEARED, 0);
            loadMapAndParent(CRCLOUDRACE_DRAG_ROCK_MAP_ID);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(CRCLOUDRACE_DRAG_ROCK_MAP_ID), 0);
            (*gMapEventInterface)->setObjGroupStatus(CRCLOUDRACE_DRAG_ROCK_MAP_ID, 1, 1);
            break;
        }
    }
    return 0;
}

#pragma dont_inline on
void crcloudrace_updateCompletionState(int obj, CrCloudRaceState *state) {
    f32 dist;
    int player;
    u32 near;

    dist = lbl_803E6740;
    player = (int)Obj_GetPlayerObject();
    if (GameBit_Get(CRCLOUDRACE_GAMEBIT_IN_FINISH_VOLUME) == 0) {
        if (GameBit_Get(CRCLOUDRACE_GAMEBIT_ABORT_TRIGGER) != 0) {
            state->phase = CRCLOUDRACE_PHASE_ABORT;
            setMotionBlur(0, lbl_803E6744);
            GameBit_Set(CRCLOUDRACE_GAMEBIT_RACE_ACTIVE, 0);
            GameBit_Set(CRCLOUDRACE_GAMEBIT_RACE_STARTED, 0);
        }
    } else {
        GameBit_Set(CRCLOUDRACE_GAMEBIT_IN_FINISH_VOLUME, 1);
        setMotionBlur(0, lbl_803E6744);
        if (GameBit_Get(CRCLOUDRACE_GAMEBIT_RACE_CAN_FINISH) != 0 && fn_802972A8(player) == 0) {
            near = ObjGroup_FindNearestObject(CRCLOUDRACE_NEARBY_TOTEM_GROUP, obj, &dist);
            if (near != 0) {
                (*(void (**)(int, int))((char *)*((GameObject *)near)->anim.dll + 0x20))(near, 1);
            }
            state->phase = CRCLOUDRACE_PHASE_RESET_TO_START;
        }
    }
}
#pragma dont_inline reset

void crcloudrace_updateRaceState(int obj) {
    CrCloudRaceObject *raceObj;
    CrCloudRaceState *inner;
    int player;

    raceObj = (CrCloudRaceObject *)obj;
    inner = raceObj->state;
    player = (int)Obj_GetPlayerObject();
    switch (inner->phase) {
    case CRCLOUDRACE_PHASE_START:
        if (GameBit_Get(CRCLOUDRACE_GAMEBIT_TOTEM_GATE) != 0) {
            GameBit_Set(CRCLOUDRACE_GAMEBIT_TOTEM_LATCH, 1);
        }
        if (fn_802972A8(player) != 0) {
            GameBit_Set(CRCLOUDRACE_GAMEBIT_RACE_STARTED, 1);
            GameBit_Set(CRCLOUDRACE_GAMEBIT_RACE_ACTIVE, 1);
            inner->phase = CRCLOUDRACE_PHASE_RACING;
            unlockLevel(0, 0, 1);
        }
        break;
    case CRCLOUDRACE_PHASE_RACING:
        crcloudrace_updateCompletionState(obj, inner);
        break;
    case CRCLOUDRACE_PHASE_ABORT:
        GameBit_Set(CRCLOUDRACE_GAMEBIT_TOTEM_LATCH, 0);
        inner->phase = CRCLOUDRACE_PHASE_COUNTDOWN;
        s16toFloat((char *)inner->timer, CRCLOUDRACE_COUNTDOWN_FRAMES);
        break;
    case CRCLOUDRACE_PHASE_COUNTDOWN:
        if (timerCountDown((char *)inner->timer) != 0) {
            inner->phase = CRCLOUDRACE_PHASE_RELOAD_DRAG_ROCK;
        }
        break;
    case CRCLOUDRACE_PHASE_RELOAD_DRAG_ROCK:
        unlockLevel(0, 0, 1);
        loadMapAndParent(CRCLOUDRACE_DRAG_ROCK_MAP_ID);
        lockLevel(mapGetDirIdx(CRCLOUDRACE_DRAG_ROCK_MAP_ID), 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_D73, 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_983, 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_E23, 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_E1D, 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_DB8, 0);
        GameBit_Set(CRCLOUDRACE_RESET_BIT_984, 0);
        GameBit_Set(CRCLOUDRACE_GAMEBIT_DRAG_ROCK_CLEARED, 0);
        inner->phase = CRCLOUDRACE_PHASE_IDLE;
        break;
    case CRCLOUDRACE_PHASE_RESET_TO_START:
        inner->phase = CRCLOUDRACE_PHASE_START;
        break;
    case 1:
    case 6:
    default:
        inner->phase = CRCLOUDRACE_PHASE_START;
        break;
    case CRCLOUDRACE_PHASE_IDLE:
        break;
    }
}
