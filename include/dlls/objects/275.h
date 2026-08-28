#ifndef DLLS_OBJECTS_275_H_
#define DLLS_OBJECTS_275_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define SEQ_OBJ2_STATE_SIZE 0x1

typedef struct SeqObj2Placement {
    ObjPlacement base;     /* 0x00 */
    s16 usedGameBit;       /* 0x18 */
    s16 requiredGameBit;   /* 0x1A */
    u8 initialYaw;         /* 0x1C: rotation in 1/256 turns */
    u8 flags;              /* 0x1D */
    s8 sequenceId;         /* 0x1E */
    u8 modelBankIndex;     /* 0x1F */
    s16 preemptSequenceId; /* 0x20 */
    u16 sequenceParam;     /* 0x22 */
    u8 pad24[4];           /* 0x24 */
} SeqObj2Placement;

typedef struct SeqObj2State {
    u8 flags;
} SeqObj2State;

STATIC_ASSERT(offsetof(SeqObj2Placement, base) == 0x0);
STATIC_ASSERT(offsetof(SeqObj2Placement, usedGameBit) == 0x18);
STATIC_ASSERT(offsetof(SeqObj2Placement, requiredGameBit) == 0x1A);
STATIC_ASSERT(offsetof(SeqObj2Placement, initialYaw) == 0x1C);
STATIC_ASSERT(offsetof(SeqObj2Placement, flags) == 0x1D);
STATIC_ASSERT(offsetof(SeqObj2Placement, sequenceId) == 0x1E);
STATIC_ASSERT(offsetof(SeqObj2Placement, modelBankIndex) == 0x1F);
STATIC_ASSERT(offsetof(SeqObj2Placement, preemptSequenceId) == 0x20);
STATIC_ASSERT(offsetof(SeqObj2Placement, sequenceParam) == 0x22);
STATIC_ASSERT(offsetof(SeqObj2Placement, pad24) == 0x24);
STATIC_ASSERT(sizeof(SeqObj2Placement) == 0x28);

STATIC_ASSERT(offsetof(SeqObj2State, flags) == 0x0);
STATIC_ASSERT(sizeof(SeqObj2State) == SEQ_OBJ2_STATE_SIZE);

int SeqObj2_getExtraSize(void);
int SeqObj2_getObjectTypeId(void);
void SeqObj2_free(GameObject* obj);
void SeqObj2_render(void);
void SeqObj2_hitDetect(void);
void SeqObj2_update(GameObject* obj);
void SeqObj2_init(GameObject* obj, SeqObj2Placement* placement);
void SeqObj2_release(void);
void SeqObj2_initialise(void);

extern ObjectDescriptor gSeqObj2ObjDescriptor;

#endif /* DLLS_OBJECTS_275_H_ */
