#ifndef MAIN_GAMETEXT_SHARED_INTERNAL_H_
#define MAIN_GAMETEXT_SHARED_INTERNAL_H_

#include "types.h"

struct TextDisplayState;

extern char* gGameTextCommandStringCursor;
extern int gGameTextBoundsMaxX;
extern int gGameTextBoundsMinX;
extern int gGameTextBoundsMaxY;
extern int gGameTextBoundsMinY;
extern int gGameTextMeasureOnly;
extern u8 gGameTextColorA;
extern u8 gGameTextColorB;
extern u8 gGameTextColorG;
extern u8 gGameTextColorR;
extern int gGameTextRenderingById;
extern u16 gGameTextCursorX;
extern u16 gGameTextCursorY;
extern void* gGameTextStringStore;
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern int gGameTextShadowEnabled;
extern f32 gGameTextScale;
extern u8 gGameTextShadowColorB;
extern u8 gGameTextShadowColorG;
extern u8 gGameTextShadowColorR;
extern u8 sGameTextFallbackDefs[];
extern f32 gGameTextRevealProgress;
extern int gGameTextDrawnCharIndex;
extern int gGameTextRevealActive;
extern f32 gGameTextRevealSpeed;

int utf8GetNextChar(u8* str, int* outLen);
void* gameTextGetCurBox(void);
void gameTextMeasureStringBounds(char* str, int boxIdx, int* outMinX, int* outMaxX, int* outMinY, int* outMaxY);
void gameTextRenderStrs(char* str, int boxIdx);
void gameTextTickReveal(int textId, struct TextDisplayState* state);
void gameTextRenderById(int textId, int x, int y);

extern f32* gGameTextFallbackBuf;

#endif /* MAIN_GAMETEXT_SHARED_INTERNAL_H_ */
