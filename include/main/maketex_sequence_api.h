#ifndef MAIN_MAKETEX_SEQUENCE_API_H_
#define MAIN_MAKETEX_SEQUENCE_API_H_

#include "types.h"

typedef struct ObjAnimUpdateState ObjAnimUpdateState;

void seqClearTaskTexts(void);
void clearCurSeqNo(void);
void endObjSequence(int seq);
int seqStreamLookupFn_8007fff8(void* entries, int count, int key);
void objSeqInitFn_80080078(void* entries, int count);
int animatedObjGetSeqId(ObjAnimUpdateState* state);
void fn_8008020C(f32 x, f32 y, s16 rx, s16 ry, s16 rz, f32 z, f32 w);
void streamCb_80080384(void);

#endif /* MAIN_MAKETEX_SEQUENCE_API_H_ */
