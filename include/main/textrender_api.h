#ifndef MAIN_TEXTRENDER_API_H_
#define MAIN_TEXTRENDER_API_H_

#include "types.h"

typedef struct GameTextSlot {
    int opcode;
    int arg0;
    int arg1;
    int arg2;
    int arg3;
} GameTextSlot;

typedef void (*GameTextSetColorIntFn)(int r, int g, int b, int a);
extern int lbl_803DC9C8;
extern u8 lbl_803DC968;
extern GameTextSlot lbl_8033A540[];

#define gGameTextCommandCount lbl_803DC9C8
#define gGameTextCommandSlots lbl_8033A540

void subtitleFn_8001b700(void);
void subtitleStart(int x);
void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang);
void subtitleUpdateAndDraw(int mode);
void subtitleBuildLineTable(void);
int subtitleIsActive(void);
int setSubtitlesEnabled(int enabled);
void* gameTextGetPhrase(int textId, int phraseIndex);
void* gameTextGetStr(int textId);
void gameTextResetCursor(int flags);
#ifdef TEXTRENDER_DIRECT_INT_CURSOR_CALL
void gameTextSetCursor(int x, int y, int flags);
#else
void gameTextSetCursor(u16 x, u16 y, int flags);
#endif
void gameTextSetDrawFunc(void* drawFunc);
void gameTextSetWindow(u8* textBox);
f32 gameTextFn_80019c00(void);
void gameTextRun(void);
void* gameTextGet(int textId);
void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
void mainLoopDoGameText(void);
void gameTextLoadDir(int dirId);
int gameTextFn_8001b44c(int x);
void gameTextLoadForCurMap(int sourceId);
void gameTextLoadTaskText(int taskId);
void* getCurGameText(void);
int getCurLanguage(void);
void gameTextInit(void);
void gameTextInitFn_8001a234(void);
void gameTextInitFn_8001bd14(void);
void gameTextInitFn_8001c794(void);
void gameTextLoadGraphicsFn_8001a918(void);
void fn_8001BDD4(int mode);
void fn_8001BE2C(int mode);

#define gameTextSetColorInt ((GameTextSetColorIntFn)gameTextSetColor)
#define gameTextSetColorU8 gameTextSetColor
void gameTextSetWindowStrPos(int idx, int x, int y);

#endif /* MAIN_TEXTRENDER_API_H_ */
