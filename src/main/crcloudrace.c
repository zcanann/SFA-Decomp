#include "ghidra_import.h"

extern void fn_80008B74(void *obj,void *target,int animId,int flags);
extern void fn_8000A380(int param_1,int param_2,int param_3);
extern int GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void fn_8003B8F4(double scale);
extern void fn_8004350C(int param_1,int param_2,int param_3);
extern void fn_8008016C(void *timer);
extern void fn_801D7ED4(void *effect,int param_2,int param_3,int param_4,int param_5,int param_6);
extern void fn_802107CC(void *obj);
extern undefined4 fn_80210980(void *obj,undefined4 param_2,void *param_3);

extern f32 lbl_803E6748;

typedef struct CrCloudRaceState {
  u8 unk0[4];
  u8 timer[4];
  u8 phase;
  u8 flags;
  u8 unkA[2];
  u8 effect[4];
} CrCloudRaceState;

typedef struct CrCloudRaceObject {
  u8 unk0[0xb8];
  CrCloudRaceState *state;
  undefined4 (*callback)(void *obj,undefined4 param_2,void *param_3);
  u8 unkC0[0x34];
  int unkF4;
  int unkF8;
} CrCloudRaceObject;

int crcloudrace_getExtraSize(void)
{
  return sizeof(CrCloudRaceState);
}

int crcloudrace_func08(void)
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
    fn_8003B8F4((double)lbl_803E6748);
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
      fn_80008B74(obj,obj,0x174,0);
      fn_80008B74(obj,obj,0x1e1,0);
      GameBit_Set(0xdcb,0);
      fn_8004350C(0,0,1);
    }
    obj->unkF4 = 1;
  }
  fn_802107CC(obj);
  state->flags &= ~1;
  fn_801D7ED4(state->effect,1,-1,-1,0xe24,0xe8);
  fn_801D7ED4(state->effect,2,-1,-1,0xe24,0x38);
  return;
}

void crcloudrace_init(CrCloudRaceObject *obj)
{
  CrCloudRaceState *state;

  state = obj->state;
  obj->callback = fn_80210980;
  state->phase = 2;
  fn_8008016C(state->timer);
  GameBit_Set(0xe24,1);
  fn_8000A380(3,2,1000);
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
