#ifndef TRACK_INTERSECT_SCREEN_API_H_
#define TRACK_INTERSECT_SCREEN_API_H_

#include "types.h"

u32 getScreenResolution(void);
#ifdef INTERSECT_SCREEN_DIRECT_SIGNED_WIDTH_CALL
void setScreenWidth(int width);
#else
void setScreenWidth(u32 width);
#endif
void clearScreenWidth(void);

#endif /* TRACK_INTERSECT_SCREEN_API_H_ */
