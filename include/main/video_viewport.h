#ifndef MAIN_VIDEO_VIEWPORT_H_
#define MAIN_VIDEO_VIEWPORT_H_

#include "dolphin/gx/GXStruct.h"

#if defined(VERSION_GSAE01) || defined(VERSION_GSAJ01)
#define VIDEO_VIEWPORT_HEIGHT(renderMode) ((renderMode)->xfbHeight)
#else
#define VIDEO_VIEWPORT_HEIGHT(renderMode) ((renderMode)->efbHeight)
#endif

#endif /* MAIN_VIDEO_VIEWPORT_H_ */
