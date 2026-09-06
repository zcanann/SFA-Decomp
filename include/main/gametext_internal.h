#ifndef MAIN_GAMETEXT_INTERNAL_H_
#define MAIN_GAMETEXT_INTERNAL_H_

#include "global.h"
#include "main/gametext_box_api.h"

typedef struct TaskTextEntry {
    u16 textSeqId;
    u16 dirId;
    u16 objSeqId;
} TaskTextEntry;

typedef struct GameTextDef {
    u16 identifier;
    u16 count;
    u8 boxId;
    u8 alignH;
    u8 alignV;
    u8 language;
    char** strings;
} GameTextDef;

STATIC_ASSERT(sizeof(GameTextDef) == 0xc);
STATIC_ASSERT(offsetof(GameTextDef, strings) == 0x8);

#define GAMETEXT_FALLBACK_COUNT       8
#define GAMETEXT_FALLBACK_BUFFER_SIZE 0x40

extern f32 sGameTextFallbackElapsedFrames[GAMETEXT_FALLBACK_COUNT];
extern f32 sGameTextFallbackRequestDelta[GAMETEXT_FALLBACK_COUNT];
extern GameTextDef sGameTextFallbackDefs[GAMETEXT_FALLBACK_COUNT];
extern char* sGameTextFallbackStrings[GAMETEXT_FALLBACK_COUNT];
extern char sGameTextFallbackBuffers[GAMETEXT_FALLBACK_COUNT][GAMETEXT_FALLBACK_BUFFER_SIZE];
extern GameTextDef* gGameTextLastEntry;
extern f32* gGameTextFallbackRequestDelta;
extern char sGameTextPath[0x40];
extern char sGameTextCommandStringBuffer[0x800];

typedef struct TextGlyph {
    u32 key;
    u16 u;
    u16 v;
    s8 offsetX;
    s8 advanceX;
    s8 offsetY;
    s8 advanceY;
    u8 width;
    u8 height;
    u8 font;
    u8 page;
} TextGlyph;

STATIC_ASSERT(sizeof(TextGlyph) == 0x10);
STATIC_ASSERT(offsetof(TextGlyph, u) == 0x4);
STATIC_ASSERT(offsetof(TextGlyph, offsetX) == 0x8);
STATIC_ASSERT(offsetof(TextGlyph, width) == 0xc);
STATIC_ASSERT(offsetof(TextGlyph, font) == 0xe);

struct Texture;

typedef struct TextFont {
    TextGlyph* glyphs;
    GameTextDef* entries;
    int glyphCount;
    int entryCount;
    struct Texture* textures[3];
    int status;
    f32 timer;
    u8 dirId;
    u8 languageId;
    u8 pad26[2];
} TextFont;

/* Language ids; order fixed by sLanguageNameTable[] below. */
#define LANGUAGE_ENGLISH  0
#define LANGUAGE_FRENCH   1
#define LANGUAGE_GERMAN   2
#define LANGUAGE_ITALIAN  3
#define LANGUAGE_JAPANESE 4
#define LANGUAGE_SPANISH  5

typedef struct LanguageName {
    char* name;
    u8 fontId;
    u8 pad5[3];
} LanguageName;

typedef struct FontMetrics {
    u16 glyphCount;
    u8 unk02[2];
    u8 unk04;
    u8 unk05;
    u8 unk06;
    u8 pad07;
    u16 maxWidth;
    u16 lineHeight;
    u8 padc[4];
} FontMetrics;

typedef struct CtrlCharEntry {
    u32 key;
    int len;
} CtrlCharEntry;

struct TextDisplayState {
    int active;
    int charIndex;
    int f8;
    int fC;
    int f10;
};

typedef void (*GameTextDrawFunc)(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);

extern GameTextBox gTextBoxes[GAMETEXT_BOX_COUNT];
extern void* gCurTextBox;
extern GameTextDrawFunc gameTextDrawFunc;
extern TaskTextEntry gTaskTextTable[];
extern u8 gUtf8CharClassTable[];
extern int gUtf8ClassOffsetTable[];
extern TextFont* gameTextFonts;
extern int gameTextCharset;
extern int curLanguage;
extern LanguageName sLanguageNameTable[];
extern FontMetrics gGameTextFontMetrics[];
extern CtrlCharEntry gGameTextCtrlCodeArgCounts[];

extern char sLanguageNameEnglish[];
extern char sLanguageNameFrench[];
extern char sLanguageNameGerman[];
extern char sLanguageNameItalian[];
extern char sLanguageNameSpanish[];

int getControlCharLen(u32 c);

#endif /* MAIN_GAMETEXT_INTERNAL_H_ */
