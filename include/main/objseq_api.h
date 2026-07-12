#ifndef MAIN_OBJSEQ_API_H_
#define MAIN_OBJSEQ_API_H_

#include "types.h"

typedef int (*GetCurSeqNoIntFn)(void);

u8 getCurSeqNo(void);

#define getCurSeqNoInt() (((GetCurSeqNoIntFn)getCurSeqNo)())

#endif /* MAIN_OBJSEQ_API_H_ */
