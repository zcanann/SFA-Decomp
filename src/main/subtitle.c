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

SubtitleCmd* subtitleParseControlCmds(char* str, int* count);
static void subtitleBuildLineTable(void);

void* gSubtitleLineTable[0x100];

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
        if (lineIndex + 1 < gSubtitleLineCount && currentTime >= gSubtitleLineTimes[lineIndex + 1]) {
            char** lineStrs[1];
            lineStrs[0] = gSubtitleLineStrs;
            commands = subtitleParseControlCmds(lineStrs[0][lineIndex], &commandCount);
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
        gameTextShowStr(gSubtitleLineStrs[gSubtitleLineIndex], 10, 0, 0);
        if (gGameTextSequenceMode != 0) {
            gameTextSetCharset(savedCharset, 2);
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

void subtitleStop(void) {
    void** blockSlot[1];
    int zero[1];
    int blockIndex;
    int oldDelay;
    int savedDir;

    if (gSubtitleActive != 0) {
        zero[0] = 0;
        gSubtitleActive = zero[0];
        blockIndex = 0;
        blockSlot[0] = &gSubtitleLineTable[0];
        while (blockIndex < gSubtitleBlockCount) {
            if (*blockSlot[0] != NULL) {
                oldDelay = mmSetFreeDelay(0);
                mm_free(*blockSlot[0]);
                mmSetFreeDelay(oldDelay);
                *blockSlot[0] = (void*)zero[0];
            }
            blockSlot[0]++;
            blockIndex++;
        }

        savedDir = gGameTextSavedDir;
        if (savedDir != -1) {
            gameTextLoadDir(savedDir);
            gGameTextSavedDir = -1;
        }
    }
}

static void subtitleBuildLineTable(void) {
    int savedCharset;
    SubtitleLineTable* s[1];
    f32 delta;
    f32 curTime;
    GameTextDef* t;
    GameTextBox* win;
    int m;
    int i;
    char* str;
    int k;
    int total;
    int oldDelay;
    char** strLines;
    int found;
    int q;
    int n;
    int count;
    int args[3];
    f32 ftotal;
    void** blk;

    s[0] = (SubtitleLineTable*)gSubtitleLineTable;
    total = 0;
    curTime = 0.0f;
    if (gGameTextSequenceMode != 0) {
        savedCharset = gameTextGetCharset();
        gameTextSetCharset(1, 1);
    }
    t = (GameTextDef*)gameTextGet(gGameTextPendingTextId);
    win = &gTextBoxes[10];
    gSubtitleLineCount = 0;
    gSubtitleBlockCount = 0;
    for (i = 0; i < SUBTITLE_LINE_COUNT; i++) {
        s[0]->times[i] = SUBTITLE_TIME_NONE;
    }
    for (i = 0; i < t->count; i++) {
        str = t->strings[i];
        n = GameText_FindControlCodeArgs((u8*)str, TEXT_CTRL_SEQ_TIME, args);
        if (n != 0) {
            q = args[2] / 60;
            s[0]->times[gSubtitleLineCount] = (f32)(args[1] + args[0] * 60 + q);
        }
        strLines = gameTextWrapLines(str, (f32)(u32)win->maxWidth, win->scale, &count, NULL);
        if (strLines != NULL) {
            for (k = 0; k < count; k++) {
                s[0]->lines[gSubtitleLineCount++] = strLines[k];
            }
            blk = &s[0]->blocks[gSubtitleBlockCount];
            if (*blk != NULL) {
                oldDelay = mmSetFreeDelay(0);
                blk = (void**)((u8*)s[0] + gSubtitleBlockCount * 4);
                mm_free(*blk);
                mmSetFreeDelay(oldDelay);
            }
            blk = (void**)((u8*)s[0] + gSubtitleBlockCount++ * 4);
            *blk = strLines;
        }
    }
    for (k = 0; k < gSubtitleLineCount; k++) {
        if (SUBTITLE_TIME_NONE != s[0]->times[k]) {
            curTime = s[0]->times[k];
            total = GameText_CountPrintableChars((u8*)s[0]->lines[k]);
        } else {
            found = 0;
            m = k;
            for (i = 0; i < SUBTITLE_LINE_COUNT; i++) {
                ftotal = total;
                if (m < 255) {
                    if (SUBTITLE_TIME_NONE != s[0]->times[m + 1]) {
                        delta = s[0]->times[m + 1] - curTime;
                        found = 1;
                    }
                    n = GameText_CountPrintableChars((u8*)s[0]->lines[m]);
                    s[0]->times[m] = n;
                    total += n;
                    if (found != 0) {
                        for (q = m; q >= k; q--) {
                            s[0]->times[q] = s[0]->times[q + 1] - delta * (s[0]->times[q] / total);
                        }
                        break;
                    }
                    m++;
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

f32 gSubtitleLineTimes[0x100];
char* gSubtitleLineStrs[0x100];
