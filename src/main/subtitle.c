#include "main/subtitle.h"
#include "main/gametext_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_shared_internal.h"
#include "main/hud_visibility_api.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"

#define SUBTITLE_TIME_NONE 0.0001f

f32 gSubtitleTimes[SUBTITLE_LINE_COUNT];
char* gSubtitleLines[SUBTITLE_LINE_COUNT];
void* gSubtitleBlocks[SUBTITLE_LINE_COUNT];

STATIC_ASSERT(sizeof(gSubtitleBlocks) == 0x400);
STATIC_ASSERT(sizeof(gSubtitleLines) == 0x400);
STATIC_ASSERT(sizeof(gSubtitleTimes) == 0x400);

static void subtitleBuildLineTable(void) {
    int savedCharset;
    f32 intervalSeconds;
    f32 intervalStart;
    GameTextDef* text;
    GameTextBox* textBox;
    int scanLine;
    int index;
    char* sourceString;
    int lineIndex;
    int totalCharacters;
    int oldFreeDelay;
    char** wrappedLines;
    int foundNextTimestamp;
    int position;
    int count;
    int wrappedLineCount;
    int timeCode[3];
    f32 previousCharacterTotal;
    void** blockSlot;

    totalCharacters = 0;
    intervalStart = 0.0f;
    if (gGameTextSequenceMode != 0) {
        savedCharset = gameTextGetCharset();
        gameTextSetCharset(1, 1);
    }
    text = (GameTextDef*)gameTextGet(gGameTextPendingTextId);
    textBox = &gTextBoxes[10];
    gSubtitleLineCount = 0;
    gSubtitleBlockCount = 0;
    for (index = 0; index < SUBTITLE_LINE_COUNT; index++) {
        gSubtitleTimes[index] = SUBTITLE_TIME_NONE;
    }
    for (index = 0; index < text->count; index++) {
        sourceString = text->strings[index];
        count = GameText_FindControlCodeArgs((u8*)sourceString, TEXT_CTRL_SEQ_TIME, timeCode);
        if (count != 0) {
            position = timeCode[2] / 60;
            gSubtitleTimes[gSubtitleLineCount] = (f32)(timeCode[1] + timeCode[0] * 60 + position);
        }
        wrappedLines =
            gameTextWrapLines(sourceString, (f32)(u32)textBox->maxWidth, textBox->scale, &wrappedLineCount, NULL);
        if (wrappedLines != NULL) {
            for (lineIndex = 0; lineIndex < wrappedLineCount; lineIndex++) {
                gSubtitleLines[gSubtitleLineCount++] = wrappedLines[lineIndex];
            }
            blockSlot = &gSubtitleBlocks[gSubtitleBlockCount];
            if (*blockSlot != NULL) {
                oldFreeDelay = mmSetFreeDelay(0);
                blockSlot = &gSubtitleBlocks[gSubtitleBlockCount];
                mm_free(*blockSlot);
                mmSetFreeDelay(oldFreeDelay);
            }
            blockSlot = &gSubtitleBlocks[gSubtitleBlockCount++];
            *blockSlot = wrappedLines;
        }
    }
    for (lineIndex = 0; lineIndex < gSubtitleLineCount; lineIndex++) {
        if (SUBTITLE_TIME_NONE != gSubtitleTimes[lineIndex]) {
            intervalStart = gSubtitleTimes[lineIndex];
            totalCharacters = GameText_CountPrintableChars((u8*)gSubtitleLines[lineIndex]);
        } else {
            foundNextTimestamp = 0;
            scanLine = lineIndex;
            for (index = 0; index < SUBTITLE_LINE_COUNT; index++) {
                previousCharacterTotal = totalCharacters;
                if (scanLine < 255) {
                    if (SUBTITLE_TIME_NONE != gSubtitleTimes[scanLine + 1]) {
                        intervalSeconds = gSubtitleTimes[scanLine + 1] - intervalStart;
                        foundNextTimestamp = 1;
                    }
                    count = GameText_CountPrintableChars((u8*)gSubtitleLines[scanLine]);
                    gSubtitleTimes[scanLine] = count;
                    totalCharacters += count;
                    if (foundNextTimestamp != 0) {
                        for (position = scanLine; position >= lineIndex; position--) {
                            gSubtitleTimes[position] = gSubtitleTimes[position + 1] -
                                                       intervalSeconds * (gSubtitleTimes[position] / totalCharacters);
                        }
                        break;
                    }
                    scanLine++;
                }
            }
        }
    }
    gSubtitleLineIndex = 0;
    gSubtitleElapsedFrames = 0;
    gSubtitleActive = 2;
    if (gGameTextSequenceMode != 0) {
        gameTextSetCharset(savedCharset, 1);
    }
}

static inline void subtitleReleaseBlocks(void) {
    int oldDelay;
    int blockIndex;
    void** blockSlot;
    int zero;
    zero = 0;
    gSubtitleActive = zero;
    blockIndex = 0;
    blockSlot = &gSubtitleBlocks[0];
    while (blockIndex < gSubtitleBlockCount) {
        if (*blockSlot != NULL) {
            oldDelay = mmSetFreeDelay(0);
            mm_free(*blockSlot);
            mmSetFreeDelay(oldDelay);
            *blockSlot = (void*)zero;
        }
        blockSlot++;
        blockIndex++;
    }
}

void subtitleStop(void) {
    int savedDir;

    if (gSubtitleActive != 0) {
        subtitleReleaseBlocks();

        savedDir = gGameTextSavedDir;
        if (savedDir != -1) {
            gameTextLoadDir(savedDir);
            gGameTextSavedDir = -1;
        }
    }
}

void mainLoopDoGameText(void) {
    if (gGameTextSequenceMode != 0) {
        if (gameTextGetState(1) == 2 && gSubtitleActive == 1) {
            subtitleBuildLineTable();
        }
    } else {
        if (gameTextGetState(0) == 2 && gGameTextPendingDir == getCurGameText() && gSubtitleActive == 1) {
            subtitleBuildLineTable();
        }
    }
}

/* Matching exception: see docs/subtitle_matching.md. */
#pragma optimization_level 2
void subtitleUpdateAndDraw(int unused) {
    int savedCharset;
    SubtitleCmd* commands;
    int oldDelay;
    int commandCount;
    int lineIndex;
    f32 currentTime;

    if (gSubtitleActive == 2) {
        if (gGameTextSequenceMode != 0) {
            savedCharset = gameTextGetCharset();
            gameTextSetCharset(1, 2);
        }
        if (getHudHiddenFrameCount() == 0) {
            gSubtitleElapsedFrames += framesThisStep;
        }
        currentTime = gSubtitleElapsedFrames / 60.0f;
        gSubtitleCurTime = currentTime;
        lineIndex = gSubtitleLineIndex;
        if (lineIndex + 1 < gSubtitleLineCount && currentTime >= gSubtitleTimes[lineIndex + 1]) {
            char** lineStrs;
            lineStrs = gSubtitleLines;
            commands = subtitleParseControlCmds(lineStrs[lineIndex], &commandCount);
            if (commands != NULL) {
                SubtitleCmd* command = &commands[commandCount];
                while (command--, commandCount-- != 0) {
                    if (command->code == TEXT_CTRL_COLOR) {
                        SubtitleCmd* colorCommand = &commands[commandCount];
                        gSubtitleColorR = colorCommand->r;
                        gSubtitleColorG = colorCommand->g;
                        gSubtitleColorB = colorCommand->b;
                        gSubtitleColorA = colorCommand->a;
                        break;
                    }
                }
                oldDelay = mmSetFreeDelay(0);
                mm_free(commands);
                mmSetFreeDelay(oldDelay);
            }
            if (++gSubtitleLineIndex + 1 >= gSubtitleLineCount) {
                subtitleStop();
                if (gGameTextSequenceMode == 0) {
                    return;
                }
                gameTextSetCharset(savedCharset, 2);
                return;
            }
        }
        gameTextSetColor(gSubtitleColorR, gSubtitleColorG, gSubtitleColorB, gSubtitleColorA);
        gameTextShowStr(gSubtitleLines[gSubtitleLineIndex], 10, 0, 0);
        if (gGameTextSequenceMode != 0) {
            gameTextSetCharset(savedCharset, 2);
        }
    }
}
#pragma optimization_level 1
