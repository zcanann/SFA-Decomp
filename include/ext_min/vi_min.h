#ifndef EXT_MIN_VI_MIN_H_
#define EXT_MIN_VI_MIN_H_

#include "types.h"

void VISetNextFrameBuffer(void* fb);

void VIFlush(void);
void VIWaitForRetrace(void);
#endif /* EXT_MIN_VI_MIN_H_ */
