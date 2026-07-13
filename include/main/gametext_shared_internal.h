#ifndef MAIN_GAMETEXT_SHARED_INTERNAL_H_
#define MAIN_GAMETEXT_SHARED_INTERNAL_H_

#include "types.h"

struct TextDisplayState;

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

int utf8GetNextChar(u8* str, int* outLen);
char* gameStrcpy(char* dst, char* src);
void* gameTextGetCurBox(void);
void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
void gameTextRenderStrs(char* str, int boxIdx);
void textDisplayFn_800168dc(int textId, struct TextDisplayState* state);
void gameTextFn_8001658c(int textId, int x, int y);

#endif /* MAIN_GAMETEXT_SHARED_INTERNAL_H_ */
