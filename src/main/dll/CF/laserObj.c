#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern int GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void fn_80041018(int obj);

typedef struct LaserTriggerInterface {
  u8 pad00[0x20];
  int (*isEventReady)(int eventId);
} LaserTriggerInterface;

typedef struct LaserEventInterface {
  u8 pad00[0x40];
  int (*getMode)(int mapId);
  void (*triggerEvent)(int eventId,int value);
} LaserEventInterface;

extern LaserTriggerInterface **lbl_803DCA68;
extern LaserEventInterface **lbl_803DCAAC;

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
  int eventReady;
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
    mode = (u8)(*lbl_803DCAAC)->getMode((int)obj->modeIndex);
    switch (mode) {
      case 1:
        state = obj->state;
        eventReady = (*lbl_803DCA68)->isEventReady(0x2e8);
        if (eventReady != 0) {
          GameBit_Set((int)state->primarySequenceId,1);
          GameBit_Set((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
        }
        break;
      case 2:
        state = obj->state;
        eventReady = (*lbl_803DCA68)->isEventReady(0x83c);
        if (eventReady != 0) {
          GameBit_Set((int)state->primarySequenceId,1);
          GameBit_Set((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_08);
          (*lbl_803DCAAC)->triggerEvent(7,8);
          (*lbl_803DCAAC)->triggerEvent(0xd,2);
        }
        break;
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
