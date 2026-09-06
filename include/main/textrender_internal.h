#ifndef MAIN_TEXTRENDER_INTERNAL_H_
#define MAIN_TEXTRENDER_INTERNAL_H_

#include "dolphin/dvd.h"
#include "dolphin/gx/GXStruct.h"
#include "main/gametext_box_api.h"
#include "main/gametext_internal.h"
#include "main/textrender_api.h"
#include "main/texture.h"

STATIC_ASSERT(offsetof(GameTextBox, style) == 0x13);
STATIC_ASSERT(offsetof(GameTextBox, alpha) == 0x1E);
STATIC_ASSERT(sizeof(TextFont) == 0x28);
STATIC_ASSERT(sizeof(GameTextDef) == 0xc);
STATIC_ASSERT(offsetof(TextFont, status) == 0x1c);

typedef struct
{
    DVDFileInfo fileInfo;
    void* loadHandle;
    int loadedSize;
    int state;
    u8 dirId;
    u8 languageId;
    u8 active;
    u8 sourceId;
} GameTextLoadSlot;
STATIC_ASSERT(sizeof(GameTextLoadSlot) == 0x4c);
STATIC_ASSERT(offsetof(GameTextLoadSlot, loadHandle) == 0x3c);
STATIC_ASSERT(offsetof(GameTextLoadSlot, loadedSize) == 0x40);
STATIC_ASSERT(offsetof(GameTextLoadSlot, state) == 0x44);
STATIC_ASSERT(offsetof(GameTextLoadSlot, dirId) == 0x48);
STATIC_ASSERT(offsetof(GameTextLoadSlot, sourceId) == 0x4b);

typedef struct
{
    f32 fadeElapsed[8];
    f32 fadeTimers[8];
    GameTextDef fallbackDefs[8];
    char* fallbackBufPtrs[8];
    char fallbackBufs[8][0x40];
    u8 pad02c0[0xc0];
    char path[0x40];
    char commandStringBuffer[0x800];
    GameTextSlot commands[0x80];
    TextFont fonts[4];
    GameTextLoadSlot loadSlots[8];
} GameTextRuntime;
STATIC_ASSERT(offsetof(GameTextRuntime, fallbackDefs) == 0x40);
STATIC_ASSERT(offsetof(GameTextRuntime, fallbackBufPtrs) == 0xa0);
STATIC_ASSERT(offsetof(GameTextRuntime, fallbackBufs) == 0xc0);
STATIC_ASSERT(offsetof(GameTextRuntime, path) == 0x380);
STATIC_ASSERT(offsetof(GameTextRuntime, commandStringBuffer) == 0x3c0);
STATIC_ASSERT(offsetof(GameTextRuntime, commands) == 0xbc0);
STATIC_ASSERT(offsetof(GameTextRuntime, fonts) == 0x15c0);
STATIC_ASSERT(offsetof(GameTextRuntime, loadSlots) == 0x1660);

typedef struct
{
    u32 code;
    u16 r, g, b, a;
} SubtitleCmd;

/*
 * In-string formatting control codes (Unicode PUA, 0xe000..0xf8ff) and the
 * per-window horizontal alignment they select (win[0x12]). The align codes
 * set the mode; the realign switch reads it back to place the line.
 */
#define TEXT_CTRL_SEQ_ID        0xe000
#define TEXT_CTRL_SEQ_TIME      0xe018
#define TEXT_CTRL_HINT_ID       0xe020
#define TEXT_CTRL_SCALE         0xf8f4
#define TEXT_CTRL_FONT          0xf8f7
#define TEXT_CTRL_ALIGN_LEFT    0xf8f8
#define TEXT_CTRL_ALIGN_RIGHT   0xf8f9
#define TEXT_CTRL_ALIGN_CENTER  0xf8fa
#define TEXT_CTRL_ALIGN_JUSTIFY 0xf8fb
#define TEXT_CTRL_COLOR         0xf8ff

#define TEXT_ALIGN_LEFT    0
#define TEXT_ALIGN_RIGHT   1
#define TEXT_ALIGN_CENTER  2
#define TEXT_ALIGN_JUSTIFY 3


/* Per-glyph font id stored in TextGlyph.lang (characterStruct.font). Id 1 is unused. */
#define GAMETEXT_FONT_JAPANESE 0
#define GAMETEXT_FONT_ICON     2
#define GAMETEXT_FONT_FLAG     3
#define GAMETEXT_FONT_LATIN    4
#define GAMETEXT_FONT_FACE     5

/* Loaded font slot: gGameTextCharsets[] index, one per load purpose/directory. */
#define GAMETEXT_SLOT_DIALOGUE 0 /* various directories */
#define GAMETEXT_SLOT_CUTSCENE 1 /* Sequences */
#define GAMETEXT_SLOT_ERROR    2 /* Boot */
#define GAMETEXT_SLOT_HUD      3 /* Link */

#define GAMETEXT_PATH_BUFFER_OFFSET           0x380
#define GAMETEXT_COMMAND_STRING_BUFFER_OFFSET 0x3c0
#define GAMETEXT_FONT_SLOT_OFFSET             0x1610
#define GAMETEXT_LOAD_SLOTS_OFFSET            0x1660
#define GAMETEXT_LOAD_SLOT_COUNT              8
#define GAMETEXT_PENDING_SOURCE_COUNT         4
#define GAMETEXT_INVALID_DIR                  0xff
#define GAMETEXT_INVALID_LANGUAGE             6
#define GAMETEXT_MAP_DIR_COUNT                0x49
#define GAMETEXT_LANGUAGE_COUNT               6
#define GAMETEXT_SEQUENCE_SOURCE_ID           1

extern s16 gGameTextBoxTexAssets;
extern u16 gGameTextBoxCornerTexSrc[256];
extern u16 gGameTextBoxEdgeTexSrc[400];
extern Texture* gGameTextBoxCornerTexture;
extern Texture* gGameTextBoxBgTexture;
extern Texture* gGameTextBoxEdgeTexture;

#define SUBTITLE_LINE_COUNT 256

#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_LEFT  0x43b
#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_MID   0x43e
#define TEXTRENDER_TEXTURE_SUBTITLE_BOX_RIGHT 0x43d

typedef struct SubtitleLineTable
{
    void* blocks[SUBTITLE_LINE_COUNT];
    char* lines[SUBTITLE_LINE_COUNT];
    f32 times[SUBTITLE_LINE_COUNT];
} SubtitleLineTable;

extern int gGameTextSequenceMode;
extern int gSubtitleActive;
extern int gGameTextPendingDir;
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
extern int curGameTextDir;
extern int gGameTextShadowOffsetX;
extern int gGameTextShadowOffsetY;
extern u8 gGameTextBase[];
extern u8* gGameTextLastEntry;
extern char* gCurTextBuffer;
extern int gGameTextBufferIndex;
extern char gGameTextFontData[];
extern char sGameTextBlankFormat[5];
extern char sGameTextSequencePathFormat[];
extern GameTextLoadSlot curGameTexts[GAMETEXT_LOAD_SLOT_COUNT];
extern f32 gSubtitleLineTimes[0x100];
extern char* gSubtitleLineStrs[0x100];

int GameText_CountPrintableChars(u8* str);
int GameText_FindControlCodeArgs(u8* str, u32 target, int* out);
void loadGameTextSequence(int sequenceSlotDir, int sequenceId);

extern u8 sGameTextFallbackBufSlots[];
extern f32 gSubtitleCurTime;
extern u16 gGameTextSjisGlyphTable[];
extern char sGameTextMapPathFormat[];
extern int gGameTextFontTexRowPitch;
extern TextFont gGameTextCharsets[];
extern GXColor gGameTextClearColor;

#endif /* MAIN_TEXTRENDER_INTERNAL_H_ */
