#ifndef EXT_MIN_GXFIFO_MIN_H_
#define EXT_MIN_GXFIFO_MIN_H_

#include "types.h"


void GXEnableBreakPt(void* break_pt);
void GXGetGPStatus(GXBool* overhi, GXBool* underlow, GXBool* readIdle, GXBool* cmdIdle, GXBool* brkpt);
void GXDisableBreakPt(void);
#endif /* EXT_MIN_GXFIFO_MIN_H_ */
