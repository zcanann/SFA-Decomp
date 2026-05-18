#ifndef MAIN_OBJANIM_UPDATE_H_
#define MAIN_OBJANIM_UPDATE_H_

#include "ghidra_import.h"

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
} ObjAnimUpdateState;

#endif /* MAIN_OBJANIM_UPDATE_H_ */
