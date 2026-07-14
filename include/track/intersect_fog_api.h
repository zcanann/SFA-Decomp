#ifndef TRACK_INTERSECT_FOG_API_H_
#define TRACK_INTERSECT_FOG_API_H_

#include "types.h"

void _gxSetFogParams(void);
void getColor803dd01c(u8* rgbOut);

#define getColor803dd01cFloatLegacy(rgbOut) \
    (((void (*)(f32*))getColor803dd01c)((rgbOut)))

#endif /* TRACK_INTERSECT_FOG_API_H_ */
