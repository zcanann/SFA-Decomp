#ifndef MAIN_SUBTITLE_H_
#define MAIN_SUBTITLE_H_

#include "global.h"

#define SUBTITLE_LINE_COUNT 256

extern void* gSubtitleBlocks[SUBTITLE_LINE_COUNT];
extern char* gSubtitleLines[SUBTITLE_LINE_COUNT];
extern f32 gSubtitleTimes[SUBTITLE_LINE_COUNT];

void subtitleUpdateAndDraw(int unused);
void mainLoopDoGameText(void);
void subtitleStop(void);

#endif /* MAIN_SUBTITLE_H_ */
