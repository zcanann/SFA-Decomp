#ifndef DLLS_OBJECTS_274_H_
#define DLLS_OBJECTS_274_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define SEQ_OBJECT_STATE_SIZE 0x3

typedef struct ObjSeqState ObjSeqState;

/* Only the accessed placement prefix is recovered; the complete retail width is not established. */
typedef struct SeqObjectPlacement {
    ObjPlacement base;     /* 0x00 */
    s16 openGameBit;       /* 0x18 */
    s16 triggerGameBit;    /* 0x1A */
    u8 initialYaw;         /* 0x1C: rotation in 1/256 turns */
    u8 flags;              /* 0x1D */
    s8 sequenceId;         /* 0x1E: or -1 */
    u8 modelBankIndex;     /* 0x1F */
    s16 preemptSequenceId; /* 0x20 */
    u16 sequenceParam;     /* 0x22 */
    u8 warpMapId;          /* 0x24: zero means none */
} SeqObjectPlacement;

typedef struct SeqObjectState {
    u8 flags;
    s8 triggerBitState; /* 0x01: previous sampled value of triggerGameBit */
    u8 pad02;
} SeqObjectState;

STATIC_ASSERT(offsetof(SeqObjectPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(SeqObjectPlacement, openGameBit) == 0x18);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerGameBit) == 0x1A);
STATIC_ASSERT(offsetof(SeqObjectPlacement, initialYaw) == 0x1C);
STATIC_ASSERT(offsetof(SeqObjectPlacement, flags) == 0x1D);
STATIC_ASSERT(offsetof(SeqObjectPlacement, sequenceId) == 0x1E);
STATIC_ASSERT(offsetof(SeqObjectPlacement, modelBankIndex) == 0x1F);
STATIC_ASSERT(offsetof(SeqObjectPlacement, preemptSequenceId) == 0x20);
STATIC_ASSERT(offsetof(SeqObjectPlacement, sequenceParam) == 0x22);
STATIC_ASSERT(offsetof(SeqObjectPlacement, warpMapId) == 0x24);

STATIC_ASSERT(offsetof(SeqObjectState, flags) == 0x0);
STATIC_ASSERT(offsetof(SeqObjectState, triggerBitState) == 0x1);
STATIC_ASSERT(offsetof(SeqObjectState, pad02) == 0x2);
STATIC_ASSERT(sizeof(SeqObjectState) == SEQ_OBJECT_STATE_SIZE);

void objCallOnLoadCallback(GameObject* obj);
int SeqObject_getExtraSize(void);
int SeqObject_getObjectTypeId(void);
void SeqObject_free(GameObject* obj);
void SeqObject_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void SeqObject_update(GameObject* obj);
void SeqObject_init(GameObject* obj, SeqObjectPlacement* placement);

extern ObjectDescriptor gSeqObjectObjDescriptor;

#endif /* DLLS_OBJECTS_274_H_ */
