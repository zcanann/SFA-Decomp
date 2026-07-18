#ifndef TRACK_INTERSECT_DEPTH_STATE_API_H_
#define TRACK_INTERSECT_DEPTH_STATE_API_H_

#include "types.h"

void gxSetPeControl_ZCompLoc_(u8 zCompLoc);
void gxSetZMode_(u8 compareEnable, int compareFunc, u8 updateEnable);

#define gxSetPeControl_ZCompLocByteLegacy(zCompLoc)                                                                    \
    ((void (*)(u8))gxSetPeControl_ZCompLoc_)((zCompLoc))
#define gxSetZModeByteLegacy(compareEnable, compareFunc, updateEnable)                                                  \
    ((void (*)(u8, int, u8))gxSetZMode_)((compareEnable), (compareFunc), (updateEnable))

#endif /* TRACK_INTERSECT_DEPTH_STATE_API_H_ */
