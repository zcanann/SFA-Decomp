#ifndef MAIN_OBJANIM_UPDATE_H_
#define MAIN_OBJANIM_UPDATE_H_

#include "global.h"
#include "main/objanim_internal.h"
#include "main/objseq_control.h"

typedef struct ObjAnimUpdateState {
  /* Prefix shared with ObjSeqState. Sequence callbacks receive the live
     ObjSeqState through this view. */
  u8 pad00[0x24];
  f32 posOffsetDecay;
  u8 pad28[0x40 - 0x28];
  f32 posOffsetX;
  f32 posOffsetY;
  f32 posOffsetZ;
  f32 posOffsetScale;
  s16 rotOffsetX;
  s16 rotOffsetY;
  s16 rotOffsetZ;
  union {
    u8 sequenceEventActive;
    u8 movementState;
  };
  s8 sequenceSlot;
  s16 curFrame;
  s16 prevFrame;
  s16 endFrame;
  s16 pendingStartFrame;
  s16 seqCounter;
  s16 cmdCount;
  s16 animCount;
  s16 cmdCursor;
  s16 retriggerFrame;
  s16 gameBit;
  s16 moveId;
  union {
    struct {
      s8 hitVolumeA;
      s8 hitVolumeB;
    };
    s16 hitVolumePair; /* legacy callback name; this is ObjSeqState::flags */
    s16 flags;
  };
  union {
    struct {
      s8 activeHitVolumeA;
      s8 activeHitVolumeB;
    };
    s16 activeHitVolumePair; /* legacy callback name; this is ObjSeqState::savedFlags */
    s16 savedFlags;
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

STATIC_ASSERT(offsetof(ObjAnimUpdateState, posOffsetDecay) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, posOffsetX) == 0x40);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, posOffsetY) == 0x44);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, posOffsetZ) == 0x48);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, posOffsetScale) == 0x4C);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, rotOffsetX) == 0x50);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, rotOffsetY) == 0x52);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, rotOffsetZ) == 0x54);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceEventActive) == 0x56);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, sequenceSlot) == 0x57);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, curFrame) == 0x58);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, prevFrame) == 0x5A);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, endFrame) == 0x5C);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, pendingStartFrame) == 0x5E);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, seqCounter) == 0x60);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, cmdCount) == 0x62);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, animCount) == 0x64);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, cmdCursor) == 0x66);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, retriggerFrame) == 0x68);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, gameBit) == 0x6A);
STATIC_ASSERT(offsetof(ObjAnimUpdateState, moveId) == 0x6C);
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
