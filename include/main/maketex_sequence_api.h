#ifndef MAIN_MAKETEX_SEQUENCE_API_H_
#define MAIN_MAKETEX_SEQUENCE_API_H_

#include "types.h"

void seqClearTaskTexts(void);
void clearCurSeqNo(void);
void endObjSequence(int seq);
void fn_8008020C(s16 rx, s16 ry, s16 rz, f32 x, f32 y, f32 z, f32 w);
void streamCb_80080384(void);

#endif /* MAIN_MAKETEX_SEQUENCE_API_H_ */
