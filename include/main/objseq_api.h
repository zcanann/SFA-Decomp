#ifndef MAIN_OBJSEQ_API_H_
#define MAIN_OBJSEQ_API_H_

#include "types.h"

typedef int (*GetCurSeqNoIntFn)(void);

u8 getCurSeqNo(void);
void fn_80088730(u8* colorOut);

#define getCurSeqNoInt() (((GetCurSeqNoIntFn)getCurSeqNo)())

#endif /* MAIN_OBJSEQ_API_H_ */
