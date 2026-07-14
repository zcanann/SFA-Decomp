#ifndef MAIN_PI_FLUSH_API_H_
#define MAIN_PI_FLUSH_API_H_

#include "types.h"

int GXFlush_(u8 visible, int unused);

#define GXFlush_VoidIntLegacy(visible, unused) \
    (((void (*)(int, int))GXFlush_)((visible), (unused)))

#endif /* MAIN_PI_FLUSH_API_H_ */
