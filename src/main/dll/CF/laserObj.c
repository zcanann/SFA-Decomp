#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern int fn_8001FFB4(int eventId);
extern void fn_800200E8(int eventId,int value);
extern void fn_80041018(int obj);

extern undefined4* lbl_803DCA68;
extern undefined4* lbl_803DCAAC;

int laserObj_getExtraSize(void)
{
  return sizeof(LaserState);
}

int laserObj_func08(void)
{
  return 0;
}

void laserObj_free(void)
{
}

void laserObj_render(void)
{
}

void laserObj_hitDetect(void)
{
}

void laserObj_update(int param_1)
{
  LaserObject *obj;
  LaserState *state;
  uint uVar1;
  int mode;

  obj = (LaserObject *)param_1;
  if ((obj->state->sequenceLatched == '\0') &&
     (uVar1 = fn_8001FFB4((int)obj->state->secondarySequenceId), uVar1 != 0)) {
    obj->statusFlags &= ~LASER_OBJECT_STATUS_08;
  }
  else {
    obj->statusFlags |= LASER_OBJECT_STATUS_08;
  }
  fn_80041018(param_1);
  if ((obj->statusFlags & 1) != 0) {
    mode = (u8)(*(code *)(*lbl_803DCAAC + 0x40))((int)obj->modeIndex);
    if (mode != 2) {
      if ((mode < 2) && (mode != 0)) {
        state = obj->state;
        if ((*(code *)(*lbl_803DCA68 + 0x20))(0x2e8) != 0) {
          fn_800200E8((int)state->primarySequenceId,1);
          fn_800200E8((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags |= LASER_OBJECT_STATUS_08;
        }
      }
    }
    else {
      state = obj->state;
      if ((*(code *)(*lbl_803DCA68 + 0x20))(0x83c) != 0) {
        fn_800200E8((int)state->primarySequenceId,1);
        fn_800200E8((int)state->secondarySequenceId,0);
        state->sequenceLatched = 1;
        obj->statusFlags |= LASER_OBJECT_STATUS_08;
        (*(code *)(*lbl_803DCAAC + 0x44))(7,8);
        (*(code *)(*lbl_803DCAAC + 0x44))(0xd,2);
      }
    }
  }
  return;
}

void laserObj_init(LaserObject *obj,int param_2)
{
  LaserState *state;
  uint uVar1;

  state = obj->state;
  state->primarySequenceId = *(short *)(param_2 + 0x1e);
  state->secondarySequenceId = *(short *)(param_2 + 0x20);
  state->sequenceLatched = 0;
  obj->modeWord = *(s8 *)(param_2 + 0x18) << 8;
  uVar1 = fn_8001FFB4((int)state->primarySequenceId);
  if (uVar1 != 0) {
    state->sequenceLatched = 1;
    obj->statusFlags |= LASER_OBJECT_STATUS_08;
  }
  obj->objectFlags |= 0x6000;
  return;
}

void laserObj_release(void)
{
}

void laserObj_initialise(void)
{
}
