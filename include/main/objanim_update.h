#ifndef MAIN_OBJANIM_UPDATE_H_
#define MAIN_OBJANIM_UPDATE_H_

#include "ghidra_import.h"

typedef struct ObjAnimUpdateState {
  u8 pad00[0x81];
  u8 eventIds[0xA];
  u8 eventCount;
} ObjAnimUpdateState;

#endif /* MAIN_OBJANIM_UPDATE_H_ */
