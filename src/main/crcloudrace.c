#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/crcloudrace.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern void getEnvfxActImmediately(void *obj,void *target,int animId,int flags);
extern void streamFn_8000a380(int param_1,int param_2,int param_3);
extern u32 GameBit_Get(int eventId);
extern int GameBit_Set(int eventId,int value);
extern void objRenderFn_8003b8f4(double scale);
extern void unlockLevel(int param_1,int param_2,int param_3);
extern void storeZeroToFloatParam(void *timer);
void crcloudrace_updateRaceState(int obj);
int crcloudrace_completionCallback(int obj, int arg2, u8 *data);

extern f32 lbl_803E6748;
extern void loadMapAndParent(int mapId);
extern int lockLevel(int mapDir, int flags);
extern int mapGetDirIdx(int mapId);
extern MapEventInterface **gMapEventInterface;
extern int Obj_GetPlayerObject(void);
extern void setMotionBlur(int mode, f32 amount);
extern u32 fn_802972A8(int obj);
extern int ObjGroup_FindNearestObject(int kind, int obj, f32 *maxDistance);
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;
extern int timerCountDown(void *p);
extern void s16toFloat(void *p, int duration);

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

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void crcloudrace_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible)
{
  int draw;

  draw = visible;
  if (draw != 0) {
    objRenderFn_8003b8f4((double)lbl_803E6748);
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
    eventActive = GameBit_Get(0xdcb);
    if (eventActive != 0) {
      getEnvfxActImmediately(obj,obj,0x174,0);
      getEnvfxActImmediately(obj,obj,0x1e1,0);
      GameBit_Set(0xdcb,0);
      unlockLevel(0,0,1);
    }
    obj->unkF4 = 1;
  }
  crcloudrace_updateRaceState((int)obj);
  state->flags &= ~1;
  SCGameBitLatch_Update((SCGameBitLatchState *)state->effect,1,-1,-1,0xe24,0xe8);
  SCGameBitLatch_Update((SCGameBitLatchState *)state->effect,2,-1,-1,0xe24,0x38);
  return;
}

void crcloudrace_init(CrCloudRaceObject *obj)
{
  CrCloudRaceState *state;

  state = obj->state;
  obj->callback = (undefined4 (*)(void *, undefined4, void *))crcloudrace_completionCallback;
  state->phase = 2;
  storeZeroToFloatParam(state->timer);
  GameBit_Set(0xe24,1);
  streamFn_8000a380(3,2,1000);
  return;
}

#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

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

#pragma scheduling off
#pragma peephole off
int crcloudrace_completionCallback(int obj, int arg2, u8 *data) {
    int *inner = *(int **)(obj + 0xb8);
    int i;

    *(u8 *)((char *)inner + 9) |= 1;
    for (i = 0; i < *(u8 *)((char *)data + 0x8b); i++) {
        switch (data[i + 0x81]) {
        case 1:
            GameBit_Set(0xdca, 1);
            GameBit_Set(0x458, 0);
            loadMapAndParent(0xc);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0xc), 0);
            (*gMapEventInterface)->setAnimEvent(0xc, 1, 1);
            break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void crcloudrace_updateCompletionState(int obj, int *state) {
    f32 dist;
    int player;
    u32 near;

    dist = lbl_803E6740;
    player = Obj_GetPlayerObject();
    if (GameBit_Get(0x499) == 0) {
        if (GameBit_Get(0x2e8) != 0) {
            *(u8 *)((char *)state + 8) = 4;
            setMotionBlur(0, lbl_803E6744);
            GameBit_Set(0x497, 0);
            GameBit_Set(0x49d, 0);
        }
    } else {
        GameBit_Set(0x499, 1);
        setMotionBlur(0, lbl_803E6744);
        if (GameBit_Get(0x4a9) != 0 && fn_802972A8(player) == 0) {
            near = ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (near != 0) {
                (*(void (*)(int, int))(*(int *)(*(int *)(*(int *)(near + 0x68)) + 0x20)))(near, 1);
            }
            *(u8 *)((char *)state + 8) = 5;
        }
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void crcloudrace_updateRaceState(int obj) {
    int *inner;
    int player;

    inner = *(int **)(obj + 0xb8);
    player = Obj_GetPlayerObject();
    switch (*(u8 *)((char *)inner + 8)) {
    case 2:
        if (GameBit_Get(0x4a0) != 0) {
            GameBit_Set(0x4ba, 1);
        }
        if (fn_802972A8(player) != 0) {
            GameBit_Set(0x49d, 1);
            GameBit_Set(0x497, 1);
            *(u8 *)((char *)inner + 8) = 3;
            unlockLevel(0, 0, 1);
        }
        break;
    case 3:
        crcloudrace_updateCompletionState(obj, inner);
        break;
    case 4:
        GameBit_Set(0x4ba, 0);
        *(u8 *)((char *)inner + 8) = 7;
        s16toFloat((char *)inner + 4, 0xa);
        break;
    case 7:
        if (timerCountDown((char *)inner + 4) != 0) {
            *(u8 *)((char *)inner + 8) = 8;
        }
        break;
    case 8:
        unlockLevel(0, 0, 1);
        loadMapAndParent(0xc);
        lockLevel(mapGetDirIdx(0xc), 0);
        GameBit_Set(0xd73, 0);
        GameBit_Set(0x983, 0);
        GameBit_Set(0xe23, 0);
        GameBit_Set(0xe1d, 0);
        GameBit_Set(0xdb8, 0);
        GameBit_Set(0x984, 0);
        GameBit_Set(0x458, 0);
        *(u8 *)((char *)inner + 8) = 0;
        break;
    case 5:
        *(u8 *)((char *)inner + 8) = 2;
        break;
    case 1:
    case 6:
    default:
        *(u8 *)((char *)inner + 8) = 2;
        break;
    case 0:
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset
