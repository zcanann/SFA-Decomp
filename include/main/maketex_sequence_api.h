#ifndef MAIN_MAKETEX_SEQUENCE_API_H_
#define MAIN_MAKETEX_SEQUENCE_API_H_

#include "types.h"

typedef struct ObjAnimUpdateState ObjAnimUpdateState;

void seqClearTaskTexts(void);
void clearCurSeqNo(void);
void endObjSequence(int seq);
int seqPairTableLookup(void* entries, int count, int key);
void seqPairTablePrepare(void* entries, int count);
int animatedObjGetSeqId(ObjAnimUpdateState* state);
int ObjSeq_SetSlotValue(ObjAnimUpdateState* state, int value);
void ObjSeq_SetCameraTransformOverride(f32 x, f32 y, s16 rx, s16 ry, s16 rz, f32 z, f32 w);
void ObjSeq_AudioStreamCallback(void);

#endif /* MAIN_MAKETEX_SEQUENCE_API_H_ */
