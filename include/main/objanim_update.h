#ifndef MAIN_OBJANIM_UPDATE_H_
#define MAIN_OBJANIM_UPDATE_H_

#include "global.h"
#include "main/objanim_internal.h"

typedef void (*ObjAnimSequenceFreeCallback)(void *ctx, u8 *obj);
typedef int (*ObjAnimSequenceConditionCallback)(void *ctx, u8 *obj);

typedef struct ObjAnimUpdateState {
  u8 pad00[0x56];
  u8 sequenceEventActive;
  s8 sequenceSlot;
  u8 pad58[0x6E - 0x58];
  union {
    struct {
      s8 hitVolumeA;
      s8 hitVolumeB;
    };
    s16 hitVolumePair;
  };
  union {
    struct {
      s8 activeHitVolumeA;
      s8 activeHitVolumeB;
    };
    s16 activeHitVolumePair;
  };
  u8 pad72[0x80 - 0x72];
  u8 triggerCommand;
  u8 eventIds[0xA];
  u8 eventCount;
  u8 pad8C[0x90 - 0x8C];
  u8 sequenceControlFlags;
  u8 pad91[0xE8 - 0x91];
  ObjAnimSequenceFreeCallback freeCallback;
  ObjAnimSequenceConditionCallback conditionCallback;
  ObjAnimEventList animEvents;
} ObjAnimUpdateState;

STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceEventActive) == 0x56);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceSlot) == 0x57);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, hitVolumePair) == 0x6E);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, activeHitVolumePair) == 0x70);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, triggerCommand) == 0x80);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, eventIds) == 0x81);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, eventCount) == 0x8B);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceControlFlags) == 0x90);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, freeCallback) == 0xE8);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, conditionCallback) == 0xEC);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, animEvents) == 0xF0);

#endif /* MAIN_OBJANIM_UPDATE_H_ */
