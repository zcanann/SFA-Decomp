#ifndef MAIN_GAMETEXT_INTERNAL_H_
#define MAIN_GAMETEXT_INTERNAL_H_

#include "global.h"

typedef struct TaskTextEntry {
    u16 textSeqId;
    u16 dirId;
    u16 objSeqId;
} TaskTextEntry;

typedef struct GlyphEntry {
    u16 id;
    u8 pad[0xa];
} GlyphEntry;

typedef struct GameTextFont {
    int glyphs;
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

typedef struct TextSlot {
    u8 pad0[8];
    u16 f08;
    u16 f0a;
    f32 f0c;
    u8 f10;
    u8 f11;
    u8 f12;
    u8 pad13;
    s16 f14;
    s16 f16;
    s16 f18;
    s16 f1a;
    u8 pad1c[4];
} TextSlot;

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

typedef struct MeasGlyph {
    u32 key;
    u8 pad4[4];
    s8 f8;
    s8 f9;
    u8 padA[2];
    u8 fC;
    u8 padD;
    u8 lang;
    u8 padF;
} MeasGlyph;

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
extern FontSizeEntry lbl_802C8680[];
extern SpecialGlyph lbl_802C86F0[];

int getControlCharLen(u32 c);
void gameTextDrawBox(GameTextDef* def, int box, TextSlot* slot);
char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH);
void textRenderStr(char* str, TextSlot* slot, f32 x, f32 y, f32 lineH, int flag);

#endif /* MAIN_GAMETEXT_INTERNAL_H_ */
