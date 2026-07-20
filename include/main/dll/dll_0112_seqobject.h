#ifndef MAIN_DLL_DLL_0112_SEQOBJECT_H_
#define MAIN_DLL_DLL_0112_SEQOBJECT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef struct SeqObjectPlacement
{
    ObjPlacement base;
    s16 openGameBit;
    s16 triggerGameBit;
    u8 initialYaw;
    u8 flags;
    s8 triggerId;
    u8 modelBankIndex;
    s16 preemptSequenceId;
    u16 sequenceParam;
    u8 warpMapId;
    u8 pad25[3];
} SeqObjectPlacement;

STATIC_ASSERT(offsetof(SeqObjectPlacement, openGameBit) == 0x18);
STATIC_ASSERT(offsetof(SeqObjectPlacement, initialYaw) == 0x1C);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerId) == 0x1E);
STATIC_ASSERT(offsetof(SeqObjectPlacement, preemptSequenceId) == 0x20);
STATIC_ASSERT(offsetof(SeqObjectPlacement, warpMapId) == 0x24);
STATIC_ASSERT(sizeof(SeqObjectPlacement) == 0x28);

typedef struct SeqObjectState
{
    u8 flags;
    s8 triggerBitState; /* previous sampled value of triggerGameBit */
    u8 pad02;
} SeqObjectState;

STATIC_ASSERT(offsetof(SeqObjectState, triggerBitState) == 0x1);
STATIC_ASSERT(sizeof(SeqObjectState) == 0x3);

extern ObjectDescriptor gSeqObjectObjDescriptor;

void objCallOnloadCallback(GameObject* obj);
int SeqObject_SeqFn(GameObject* obj, int* unused, ObjAnimUpdateState* animUpdate);
int SeqObject_getExtraSize(void);
int SeqObject_getObjectTypeId(void);
void SeqObject_free(GameObject* obj);
void SeqObject_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SeqObject_update(GameObject* obj);
void SeqObject_init(GameObject* obj, SeqObjectPlacement* params);

#endif /* MAIN_DLL_DLL_0112_SEQOBJECT_H_ */
