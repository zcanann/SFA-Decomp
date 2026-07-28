#ifndef MAIN_GAMETEXT_INTERNAL_H_
#define MAIN_GAMETEXT_INTERNAL_H_

#include "global.h"
#include "main/gametext_box_api.h"

typedef struct TaskTextEntry {
    u16 textSeqId;
    u16 dirId;
    u16 objSeqId;
} TaskTextEntry;

typedef struct GlyphEntry {
    u16 id;
    u8 pad[0xa];
} GlyphEntry;

typedef struct MeasGlyph MeasGlyph;

typedef struct GameTextFont {
    MeasGlyph* glyphs;
    GlyphEntry* entries;
    int glyphCount;
    int count;
    u8 pad[0xc];
    int mode;
} GameTextFont;

typedef struct GameTextDef {
    u16 identifier;
    u16 count;
    u8 slotHint;
    u8 alignH;
    u8 alignV;
    u8 language;
    char** strings;
} GameTextDef;

/* Language ids; order fixed by sLanguageNameTable[] below. */
#define LANGUAGE_ENGLISH  0
#define LANGUAGE_FRENCH   1
#define LANGUAGE_GERMAN   2
#define LANGUAGE_ITALIAN  3
#define LANGUAGE_JAPANESE 4
#define LANGUAGE_SPANISH  5

typedef struct LanguageName {
    char* name;
    u8 sizeIdx;
    u8 pad5[3];
} LanguageName;

typedef struct FontSizeEntry {
    u8 pad0[0xa];
    u16 lineHeight;
    u8 padc[4];
} FontSizeEntry;

struct MeasGlyph {
    u32 key;
    u16 u;
    u16 v;
    s8 offsetX;
    s8 advanceX;
    s8 offsetY;
    s8 advanceY;
    u8 width;
    u8 height;
    u8 lang;
    u8 page;
};

typedef struct SpecialGlyph {
    u32 key;
    u32 val;
} SpecialGlyph;

struct TextDisplayState {
    int active;
    int charIndex;
    int f8;
    int fC;
    int f10;
};

extern u8 gTextBoxes[];
extern void* gCurTextBox;
extern void* gameTextDrawFunc;
extern TaskTextEntry gTaskTextTable[];
extern u8 gUtf8CharClassTable[];
extern int gUtf8ClassOffsetTable[];
extern GameTextFont* gameTextFonts;
extern int gameTextCharset;
extern int curLanguage;
extern LanguageName sLanguageNameTable[];
extern FontSizeEntry gGameTextFontMetrics[];
extern SpecialGlyph gGameTextCtrlCodeArgCounts[];

extern char sMapDirectoryNameArwing[];
extern char sMapDirectoryNameBoot[];
extern char sMapDirectoryNameCRFort[];
extern char sMapDirectoryNameDFPTop[];
extern char sMapDirectoryNameDesert[];
extern char sMapDirectoryNameLINKG[];
extern char sMapDirectoryNameLink[];
extern char sMapDirectoryNameLinkB[];
extern char sMapDirectoryNameLinkC[];
extern char sMapDirectoryNameLinkD[];
extern char sMapDirectoryNameLinkE[];
extern char sMapDirectoryNameLinkF[];
extern char sMapDirectoryNameLinkH[];
extern char sMapDirectoryNameLinkJ[];
extern char sMapDirectoryNameMMPass[];
extern char sMapDirectoryNameNWastes[];
extern char sMapDirectoryNameShop[];
extern char sMapDirectoryNameSwapHol[];
extern char sMapDirectoryNameVolcano[];
extern char sMapDirectoryNameWarlock[];
extern char sLanguageNameEnglish[];
extern char sLanguageNameFrench[];
extern char sLanguageNameGerman[];
extern char sLanguageNameItalian[];
extern char sLanguageNameSpanish[];

int getControlCharLen(u32 c);

#endif /* MAIN_GAMETEXT_INTERNAL_H_ */
