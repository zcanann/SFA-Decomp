#ifndef MAIN_GAMETEXT_H_
#define MAIN_GAMETEXT_H_

#include "types.h"
#include "main/gametext_box_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"

typedef struct TextDisplayState TextDisplayState;
typedef void (*GameTextSetColorU8Fn)(u8 r, u8 g, u8 b, u8 a);

extern char* lbl_803DC9C4;
extern int lbl_803DC9AC;
extern int lbl_803DC9B0;
extern int lbl_803DC9B4;
extern int lbl_803DC9B8;
extern int lbl_803DC9BC;
extern u8 lbl_803DC9A4;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A7;
extern int lbl_803DC9C0;
extern u16 lbl_803DC9AA;
extern u16 lbl_803DC9A8;
extern void* lbl_803DB378;
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern int lbl_803DC984;
extern f32 lbl_803DC9A0;
extern u8 lbl_803DC990;
extern u8 lbl_803DC991;
extern u8 lbl_803DC992;
extern u8 lbl_803399C0[];
extern f32 lbl_803DC994;
extern int lbl_803DC998;
extern int lbl_803DC99C;
extern f32 lbl_803DE700;
extern f32 lbl_803DB3D0;

void gameTextAppendStr(char* str, int arg2);
void* gameTextGet(int textId);
void gameTextSetColor(int r, int g, int b, int a);
void gameTextRun(void);
void* gameTextGetCurBox(void);
void gameTextFn_80016c18(int a, int b);
void gameTextFreePhrase(int* phrase);
int gameTextGetTaskText(int id, int* outTextSeqId, int* outDirId);
void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY);
void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextRenderStrs(char* str, int boxIdx);
void textDisplayFn_800168dc(int textId, TextDisplayState* state);
void gameTextFn_8001658c(int a, int b, int c);
int isSpace(u32 c);
int utf8GetNextChar(u8* str, int* outLen);
char* gameStrcpy(char* dst, char* src);

/* Preserve the byte-argument call view used by a few exact-match callers. */
#define gameTextSetColorU8(r, g, b, a) (((GameTextSetColorU8Fn)gameTextSetColor)((r), (g), (b), (a)))

#endif /* MAIN_GAMETEXT_H_ */
