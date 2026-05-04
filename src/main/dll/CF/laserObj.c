#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void fn_80041018(int obj);

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

#pragma scheduling off
#pragma peephole off
void laserObj_update(LaserObject *obj)
{
  LaserState *state;
  u32 secondarySequenceSet;
  int eventReady;
  int mode;

  if ((obj->state->sequenceLatched == '\0') &&
     (secondarySequenceSet = GameBit_Get((int)obj->state->secondarySequenceId),
      secondarySequenceSet != 0)) {
    obj->statusFlags = (u8)(obj->statusFlags & ~LASER_OBJECT_STATUS_DISABLED);
  }
  else {
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
  }
  fn_80041018((int)obj);
  if ((obj->statusFlags & LASER_OBJECT_STATUS_ACTIVE) != 0) {
    mode = (u8)(*lbl_803DCAAC)->getMode((int)obj->modeIndex);
    switch (mode) {
      case LASEROBJ_MODE_SEQUENCE_A:
        state = obj->state;
        eventReady = (*lbl_803DCA68)->isEventReady(LASEROBJ_SEQUENCE_A_EVENT);
        if (eventReady != 0) {
          GameBit_Set((int)state->primarySequenceId,1);
          GameBit_Set((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
        }
        break;
      case LASEROBJ_MODE_SEQUENCE_B:
        state = obj->state;
        eventReady = (*lbl_803DCA68)->isEventReady(LASEROBJ_SEQUENCE_B_EVENT);
        if (eventReady != 0) {
          GameBit_Set((int)state->primarySequenceId,1);
          GameBit_Set((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
          (*lbl_803DCAAC)->triggerEvent(LASEROBJ_SEQUENCE_B_TRIGGER_A,
                                        LASEROBJ_SEQUENCE_B_TRIGGER_A_VALUE);
          (*lbl_803DCAAC)->triggerEvent(LASEROBJ_SEQUENCE_B_TRIGGER_B,
                                        LASEROBJ_SEQUENCE_B_TRIGGER_B_VALUE);
        }
        break;
    }
  }
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void laserObj_init(LaserObject *obj,LaserObjectMapData *mapData)
{
  LaserState *state;
  u32 primarySequenceSet;

  state = obj->state;
  state->primarySequenceId = mapData->primarySequenceId;
  state->secondarySequenceId = mapData->secondarySequenceId;
  state->sequenceLatched = 0;
  obj->modeWord = (s16)(mapData->modeIndex << LASEROBJ_MODE_WORD_SHIFT);
  primarySequenceSet = GameBit_Get((int)state->primarySequenceId);
  if (primarySequenceSet != 0) {
    state->sequenceLatched = 1;
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
  }
  obj->objectFlags = (u16)(obj->objectFlags | LASER_OBJECT_FLAGS_SEQUENCE_CONTROL);
  return;
}
#pragma peephole reset
#pragma scheduling reset

void laserObj_release(void)
{
}

void laserObj_initialise(void)
{
}
