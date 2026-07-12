#ifndef MAIN_GAMETEXT_H_
#define MAIN_GAMETEXT_H_

#include "types.h"

typedef struct TextDisplayState TextDisplayState;
typedef void (*GameTextSetColorU8Fn)(u8 r, u8 g, u8 b, u8 a);

void gameTextAppendStr(char* str, int arg2);
void* gameTextGet(int textId);
int gameTextGetCharset(void);
void gameTextSetCharset(int charset, int flags);
void gameTextSetColor(int r, int g, int b, int a);
void gameTextRun(void);
void* gameTextGetCurBox(void);
void gameTextFn_80016c18(int a, int b);
void gameTextFreePhrase(int* phrase);
void gameTextFn_80016810(int a, int b, int c);
int gameTextGetTaskText(int id, int* outTextSeqId, int* outDirId);
void gameTextShowTimeStr(char* str);
void gameTextShow(int a);
void gameTextShowStr(char* text, int box, int arg2, int arg3);
void* gameTextGetBox(int box);
void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY);
void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextRenderStrs(char* str, int boxIdx);
void textDisplayFn_800168dc(int textId, TextDisplayState* state);
void gameTextFn_8001658c(int a, int b, int c);
int isSpace(u32 c);
int utf8GetNextChar(u8* str, int* outLen);

/* Preserve the byte-argument call view used by a few exact-match callers. */
#define gameTextSetColorU8(r, g, b, a) (((GameTextSetColorU8Fn)gameTextSetColor)((r), (g), (b), (a)))

#endif /* MAIN_GAMETEXT_H_ */
