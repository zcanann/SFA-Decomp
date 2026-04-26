#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern int GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
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
     (uVar1 = GameBit_Get((int)obj->state->secondarySequenceId), uVar1 != 0)) {
    obj->statusFlags = (u8)(obj->statusFlags & ~LASER_OBJECT_STATUS_08);
  }
  else {
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
  }
  fn_80041018(param_1);
  if ((obj->statusFlags & 1) != 0) {
    mode = (u8)(*(code *)(*lbl_803DCAAC + 0x40))((int)obj->modeIndex);
    if (mode != 2) {
      if ((mode < 2) && (mode >= 1)) {
        state = obj->state;
        if ((*(code *)(*lbl_803DCA68 + 0x20))(0x2e8) != 0) {
          GameBit_Set((int)state->primarySequenceId,1);
          GameBit_Set((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
        }
      }
    }
    else {
      state = obj->state;
      if ((*(code *)(*lbl_803DCA68 + 0x20))(0x83c) != 0) {
        GameBit_Set((int)state->primarySequenceId,1);
        GameBit_Set((int)state->secondarySequenceId,0);
        state->sequenceLatched = 1;
        obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
        (*(code *)(*lbl_803DCAAC + 0x44))(7,8);
        (*(code *)(*lbl_803DCAAC + 0x44))(0xd,2);
      }
    }
  }
  return;
}

void laserObj_init(LaserObject *obj,LaserObjectMapData *mapData)
{
  LaserState *state;
  uint uVar1;

  state = obj->state;
  state->primarySequenceId = mapData->primarySequenceId;
  state->secondarySequenceId = mapData->secondarySequenceId;
  state->sequenceLatched = 0;
  obj->modeWord = (s16)(mapData->modeIndex << 8);
  uVar1 = GameBit_Get((int)state->primarySequenceId);
  if (uVar1 != 0) {
    state->sequenceLatched = 1;
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
  }
  obj->objectFlags = (u16)(obj->objectFlags | 0x6000);
  return;
}

void laserObj_release(void)
{
}

void laserObj_initialise(void)
{
}
