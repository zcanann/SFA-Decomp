#ifndef MAIN_TEXTRENDER_INTERNAL_H_
#define MAIN_TEXTRENDER_INTERNAL_H_

#include "main/texture.h"

typedef struct GlyphResource802CA100 {
    u16 rows0[320];
    void* embedded;
    u16 rows1[78];
} GlyphResource802CA100;

extern s16 gGameTextBoxTexAssets;
extern u16 gGameTextBoxCornerTexSrc[256];
extern GlyphResource802CA100 lbl_802CA100;
extern Texture* gGameTextBoxCornerTexture;
extern Texture* gGameTextBoxBgTexture;
extern Texture* gGameTextBoxEdgeTexture;

#define SUBTITLE_LINE_COUNT 256

#define TEXT_CTRL_SEQ_TIME 0xe018

#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_LEFT  0x43b
#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_MID   0x43e
#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_RIGHT 0x43d

typedef struct GameTextBox
{
    u8 unk00[8];
    u16 width;
    u16 height;
    u8 unk0C[6];
    u8 alignment;
    u8 style;
    s16 x;
    s16 y;
    s16 cursorX;
    s16 cursorY;
    u16 flags;
    u8 alpha;
    u8 unk1F;
} GameTextBox;

typedef struct SubtitleLineTable
{
    void* blocks[SUBTITLE_LINE_COUNT];
    char* lines[SUBTITLE_LINE_COUNT];
    f32 times[SUBTITLE_LINE_COUNT];
} SubtitleLineTable;

typedef struct SubtitleTextEntry
{
    u8 pad0[2];
    u16 count;
    u8 pad4[4];
    char** strs;
} SubtitleTextEntry;

extern GameTextBox gTextBoxes[];
extern f32 gSubtitleNoTimeSentinel;
extern int gGameTextSequenceMode;
extern int gSubtitleActive;
extern void* gGameTextPendingDir;
extern int gSubtitlesEnabled;
extern int gGameTextPendingTextId;
extern u8 gSubtitleColorR;
extern u8 gSubtitleColorG;
extern u8 gSubtitleColorB;
extern u8 gSubtitleColorA;
extern int gSubtitleBlockCount;
extern int gSubtitleLineIndex;
extern int gSubtitleElapsedFrames;
extern int gSubtitleLineCount;
extern void* gSubtitleLineTable[0x100];
extern int gGameTextSavedDir;
extern s16 gGameTextTaskTextAllowList[12];
extern int gGameTextBoxCornerInset;
extern int gGameTextBoxInset;
extern int gGameTextBoxColorR;
extern int gGameTextBoxColorG;
extern int gGameTextBoxColorB;
extern int gGameTextBoxColorA;
extern Texture* gSubtitleBoxTextures[];
extern Texture* gGameTextBoxFrameTextures[];
extern void* gCurTextBox;

int GameText_CountPrintableChars(u8* str);
int GameText_FindControlCodeArgs(u8* str, u32 target, int* out);
void loadGameTextSequence(int sequenceSlotDir, int sequenceId);

#endif /* MAIN_TEXTRENDER_INTERNAL_H_ */
