#ifndef MAIN_SUBTITLE_H_
#define MAIN_SUBTITLE_H_

#include "global.h"

#define SUBTITLE_LINE_COUNT 256

typedef struct SubtitleLineTable {
    void* blocks[SUBTITLE_LINE_COUNT];
    char* lines[SUBTITLE_LINE_COUNT];
    f32 times[SUBTITLE_LINE_COUNT];
} SubtitleLineTable;

STATIC_ASSERT(offsetof(SubtitleLineTable, blocks) == 0x000);
STATIC_ASSERT(offsetof(SubtitleLineTable, lines) == 0x400);
STATIC_ASSERT(offsetof(SubtitleLineTable, times) == 0x800);
STATIC_ASSERT(sizeof(SubtitleLineTable) == 0xc00);

extern SubtitleLineTable gSubtitleLineTable;

void subtitleUpdateAndDraw(int unused);
void mainLoopDoGameText(void);
void subtitleStop(void);

#endif /* MAIN_SUBTITLE_H_ */
