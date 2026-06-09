#include "main/dll/CF/laser.h"
#include "main/gameplay_runtime.h"

int laserObj_getExtraSize(void)
{
  return sizeof(LaserState);
}

int laserObj_getObjectTypeId(void)
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

void laserObj_update(LaserObject *obj)
{
  LaserState *state;
  u32 secondaryGameBitSet;
  int eventReady;
  int mode;

  if ((obj->state->gameBitLatched == '\0') &&
     (secondaryGameBitSet = GameBit_Get((int)obj->state->secondaryGameBit),
      secondaryGameBitSet != 0)) {
    obj->statusFlags = (u8)(obj->statusFlags & ~LASER_OBJECT_STATUS_DISABLED);
  }
  else {
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
  }
  objRenderFn_80041018((int)obj);
  if ((obj->statusFlags & LASER_OBJECT_STATUS_ACTIVE) != 0) {
    mode = (u8)(*gMapEventInterface)->getMode((int)obj->modeIndex);
    switch (mode) {
      case LASEROBJ_MODE_SEQUENCE_A:
        state = obj->state;
        eventReady = (*gGameUIInterface)->isEventReady(LASEROBJ_SEQUENCE_A_EVENT);
        if (eventReady != 0) {
          GameBit_Set((int)state->primaryGameBit,1);
          GameBit_Set((int)state->secondaryGameBit,0);
          state->gameBitLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
        }
        break;
      case LASEROBJ_MODE_SEQUENCE_B:
        state = obj->state;
        eventReady = (*gGameUIInterface)->isEventReady(LASEROBJ_SEQUENCE_B_EVENT);
        if (eventReady != 0) {
          GameBit_Set((int)state->primaryGameBit,1);
          GameBit_Set((int)state->secondaryGameBit,0);
          state->gameBitLatched = 1;
          obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
          (*gMapEventInterface)->setMode(LASEROBJ_SEQUENCE_B_MODE_MAP_A,
                                         LASEROBJ_SEQUENCE_B_MODE_A);
          (*gMapEventInterface)->setMode(LASEROBJ_SEQUENCE_B_MODE_MAP_B,
                                         LASEROBJ_SEQUENCE_B_MODE_B);
        }
        break;
    }
  }
  return;
}


void laserObj_init(LaserObject *obj,LaserObjectMapData *mapData)
{
  LaserState *state;
  u32 primaryGameBitSet;

  state = obj->state;
  state->primaryGameBit = mapData->primaryGameBit;
  state->secondaryGameBit = mapData->secondaryGameBit;
  state->gameBitLatched = 0;
  obj->modeWord = (s16)(mapData->modeIndex << LASEROBJ_MODE_WORD_SHIFT);
  primaryGameBitSet = GameBit_Get((int)state->primaryGameBit);
  if (primaryGameBitSet != 0) {
    state->gameBitLatched = 1;
    obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
  }
  obj->objectFlags = (u16)(obj->objectFlags | LASER_OBJECT_FLAGS_SEQUENCE_CONTROL);
  return;
}

void laserObj_release(void)
{
}

void laserObj_initialise(void)
{
}

ObjectDescriptor gLaserObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    laserObj_initialise,
    laserObj_release,
    0,
    (ObjectDescriptorCallback)laserObj_init,
    (ObjectDescriptorCallback)laserObj_update,
    laserObj_hitDetect,
    laserObj_render,
    laserObj_free,
    (ObjectDescriptorCallback)laserObj_getObjectTypeId,
    laserObj_getExtraSize,
};
