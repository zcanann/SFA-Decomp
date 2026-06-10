#ifndef MAIN_OBJANIM_UPDATE_H_
#define MAIN_OBJANIM_UPDATE_H_

#include "global.h"

typedef struct ObjAnimUpdateState {
  u8 pad00[0x56];
  u8 sequenceEventActive;
  u8 pad57[0x6E - 0x57];
  union {
    struct {
      s8 hitVolumeA;
      s8 hitVolumeB;
    };
    s16 hitVolumePair;
  };
  u8 pad70[0x81 - 0x70];
  u8 eventIds[0xA];
  u8 eventCount;
  u8 pad8C[0xE8 - 0x8C];
  void *sequenceCallback;
} ObjAnimUpdateState;

STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceEventActive) == 0x56);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, hitVolumePair) == 0x6E);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, eventIds) == 0x81);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, eventCount) == 0x8B);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceCallback) == 0xE8);

#endif /* MAIN_OBJANIM_UPDATE_H_ */
