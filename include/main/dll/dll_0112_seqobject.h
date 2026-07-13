#ifndef MAIN_DLL_DLL_0112_SEQOBJECT_H_
#define MAIN_DLL_DLL_0112_SEQOBJECT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

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

typedef struct SeqObjectState
{
    u8 flags;
    s8 triggerBitState;
    u8 pad02;
} SeqObjectState;

extern u32 gSeqObjectObjDescriptor[14];

void objCallOnloadCallback(GameObject* obj);
int SeqObject_SeqFn(GameObject* obj, int* unused, ObjAnimUpdateState* animUpdate);
int SeqObject_getExtraSize(void);
int SeqObject_getObjectTypeId(void);
void SeqObject_free(GameObject* obj);
void SeqObject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SeqObject_update(GameObject* obj);
void SeqObject_init(GameObject* obj, SeqObjectPlacement* params);

#endif /* MAIN_DLL_DLL_0112_SEQOBJECT_H_ */
